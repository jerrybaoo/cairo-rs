#[cfg(feature = "parity-scale-codec")]
use crate::serde::deserialize_program::get_hints_tree;
use crate::serde::deserialize_program::{parse_program, ProgramJson, Reference, ValueAddress};
use crate::stdlib::{
    collections::{BTreeMap, HashMap},
    prelude::*,
    sync::Arc,
};

#[cfg(feature = "cairo-1-hints")]
use crate::serde::deserialize_program::{ApTracking, FlowTrackingData};
use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::{
        deserialize_and_parse_program, Attribute, BuiltinName, HintParams, Identifier,
        InstructionLocation, ReferenceManager,
    },
    types::{errors::program_errors::ProgramError, relocatable::MaybeRelocatable},
};
#[cfg(feature = "cairo-1-hints")]
use cairo_lang_casm_contract_class::CasmContractClass;
use core::num::NonZeroUsize;
use felt::{Felt252, PRIME_STR};
#[cfg(feature = "parity-scale-codec")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "std")]
use std::path::Path;

#[cfg(all(feature = "arbitrary", feature = "std"))]
use arbitrary::{Arbitrary, Unstructured};

// NOTE: `Program` has been split in two containing some data that will be deep-copied
// and some that will be allocated on the heap inside an `Arc<_>`.
// This is because it has been reported that cloning the whole structure when creating
// a `CairoRunner` becomes a bottleneck, but the following solutions were tried and
// discarded:
// - Store only a reference in `CairoRunner` rather than cloning; this doesn't work
//   because then we need to introduce explicit lifetimes, which broke `cairo-vm-py`
//   since PyO3 doesn't support Python objects containing structures with lifetimes.
// - Directly pass an `Arc<Program>` to `CairoRunner::new()` and simply copy that:
//   there was a prohibitive performance hit of 10-15% when doing so, most likely
//   either because of branch mispredictions or the extra level of indirection going
//   through a random location on the heap rather than the likely-to-be-cached spot
//   on the stack.
//
// So, the compromise was to identify which data was less used and avoid copying that,
// using `Arc<_>`, while the most accessed fields remain on the stack for the main
// loop to access. The fields in `SharedProgramData` are either preprocessed and
// copied explicitly (_in addition_ to the clone of `Program`) or are used only in
// exceptional circumstances, such as when reconstructing a backtrace on execution
// failures.
// Fields in `Program` (other than `SharedProgramData` itself) are used by the main logic.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct SharedProgramData {
    pub(crate) data: Vec<MaybeRelocatable>,
    pub(crate) hints: Vec<HintParams>,
    /// This maps a PC to the range of hints in `hints` that correspond to it.
    pub(crate) hints_ranges: Vec<HintRange>,
    pub(crate) main: Option<usize>,
    //start and end labels will only be used in proof-mode
    pub(crate) start: Option<usize>,
    pub(crate) end: Option<usize>,
    pub(crate) error_message_attributes: Vec<Attribute>,
    pub(crate) instruction_locations: Option<HashMap<usize, InstructionLocation>>,
    pub(crate) identifiers: HashMap<String, Identifier>,
    pub(crate) reference_manager: Vec<HintReference>,
}

#[cfg(all(feature = "arbitrary", feature = "std"))]
impl<'a> Arbitrary<'a> for SharedProgramData {
    /// Create an arbitary [`SharedProgramData`] using `flatten_hints` to generate `hints` and
    /// `hints_ranges`
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut data = Vec::new();
        let len = usize::arbitrary(u)?;
        for i in 0..len {
            let instruction = u64::arbitrary(u)?;
            data.push(MaybeRelocatable::from(Felt252::from(instruction)));
            // Check if the Imm flag is on and add an immediate value if it is
            if instruction & 0x0004000000000000 != 0 && i < len - 1 {
                data.push(MaybeRelocatable::from(Felt252::arbitrary(u)?));
            }
        }

        let raw_hints = BTreeMap::<usize, Vec<HintParams>>::arbitrary(u)?;
        let (hints, hints_ranges) = Program::flatten_hints(&raw_hints, data.len())
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(SharedProgramData {
            data,
            hints,
            hints_ranges,
            main: Option::<usize>::arbitrary(u)?,
            start: Option::<usize>::arbitrary(u)?,
            end: Option::<usize>::arbitrary(u)?,
            error_message_attributes: Vec::<Attribute>::arbitrary(u)?,
            instruction_locations: Option::<HashMap<usize, InstructionLocation>>::arbitrary(u)?,
            identifiers: HashMap::<String, Identifier>::arbitrary(u)?,
            reference_manager: Vec::<HintReference>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "parity-scale-codec")]
impl Encode for SharedProgramData {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        let hints: Vec<(u64, Vec<HintParams>)> = get_hints_tree(&self)
            .into_iter()
            .map(|(id, params)| (id as u64, params.clone()))
            .collect::<Vec<(u64, Vec<HintParams>)>>();

        // Convert the hashmap to a vec because it's encodable.
        let mut instruction_locations: Option<Vec<(u64, InstructionLocation)>> =
            self.instruction_locations.as_ref().map(|i| {
                i.iter()
                    .map(|(id, location)| (*id as u64, location.clone()))
                    .collect::<Vec<_>>()
            });

        if let Some(il) = instruction_locations.as_mut() {
            il.sort_by(|a, b| a.0.cmp(&b.0));
        }

        let mut identifiers = self
            .identifiers
            .iter()
            .map(|(s, i)| (s.clone(), i.clone()))
            .collect::<Vec<(String, Identifier)>>();

        identifiers.sort_by(|a, b| a.0.cmp(&b.0));

        parity_scale_codec::Encode::encode_to(&self.data, dest);
        parity_scale_codec::Encode::encode_to(&hints, dest);
        parity_scale_codec::Encode::encode_to(&self.main.map(|v| v as u64), dest);
        parity_scale_codec::Encode::encode_to(&self.start.map(|v| v as u64), dest);
        parity_scale_codec::Encode::encode_to(&self.end.map(|v| v as u64), dest);
        parity_scale_codec::Encode::encode_to(&self.error_message_attributes, dest);
        parity_scale_codec::Encode::encode_to(&instruction_locations, dest);
        parity_scale_codec::Encode::encode_to(&identifiers, dest);
        parity_scale_codec::Encode::encode_to(&self.reference_manager, dest);
    }
}

#[cfg(feature = "parity-scale-codec")]
impl parity_scale_codec::EncodeLike for SharedProgramData {}

#[cfg(feature = "parity-scale-codec")]
impl Decode for SharedProgramData {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let data = <Vec<MaybeRelocatable> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::data`"))?;

        let hints = <Vec<(u64, Vec<HintParams>)>>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::hints`"))?
            .into_iter()
            .map(|(id, hints)| (id as usize, hints))
            .collect::<BTreeMap<_, _>>();

        let (hints, hints_ranges) = Program::flatten_hints(&hints, data.len()).unwrap();

        let main = <Option<u64> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::main`"))?
            .map(|v| v as usize);

        let start = <Option<u64> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::start`"))?
            .map(|v| v as usize);

        let end = <Option<u64> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::end`"))?
            .map(|v| v as usize);

        let error_message_attributes = <Vec<Attribute> as Decode>::decode(input).map_err(|e| {
            e.chain("Could not decode `SharedProgramData::error_message_attributes`")
        })?;

        let instruction_locations = <Option<Vec<(u64, InstructionLocation)>>>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::instruction_locations`"))?
            .map(|il| {
                il.into_iter()
                    .map(|(id, location)| (id as usize, location))
                    .collect::<HashMap<_, _>>()
            });

        let identifiers = <Vec<(String, Identifier)> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::identifiers`"))?
            .into_iter()
            .collect::<HashMap<String, Identifier>>();

        let reference_manager = <Vec<HintReference> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `SharedProgramData::reference_manager`"))?;

        Ok(SharedProgramData {
            data,
            hints,
            hints_ranges,
            main,
            start,
            end,
            error_message_attributes,
            instruction_locations,
            identifiers,
            reference_manager,
        })
    }
}

/// Represents a range of hints corresponding to a PC.
///
/// Is [`None`] if the range is empty, and it is [`Some`] tuple `(start, length)` otherwise.
type HintRange = Option<(usize, NonZeroUsize)>;

#[cfg_attr(all(feature = "arbitrary", feature = "std"), derive(Arbitrary))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub shared_program_data: Arc<SharedProgramData>,
    pub constants: HashMap<String, Felt252>,
    pub builtins: Vec<BuiltinName>,
}

#[cfg(feature = "parity-scale-codec")]
impl Encode for Program {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        let mut constants = self
            .constants
            .iter()
            .map(|(s, f)| (s.clone(), f.clone()))
            .collect::<Vec<(String, Felt252)>>();

        constants.sort_by(|a, b| a.0.cmp(&b.0));

        parity_scale_codec::Encode::encode_to(&self.shared_program_data, dest);
        parity_scale_codec::Encode::encode_to(&constants, dest);
        parity_scale_codec::Encode::encode_to(&self.builtins, dest);
    }
}

#[cfg(feature = "parity-scale-codec")]
impl parity_scale_codec::EncodeLike for Program {}

#[cfg(feature = "parity-scale-codec")]
impl Decode for Program {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let shared_program_data = <Arc<SharedProgramData> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `Program::shared_program_data`"))?;
        let constants = <Vec<(String, Felt252)> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `Program::constants`"))?
            .into_iter()
            .collect::<HashMap<_, _>>();
        let builtins = <Vec<BuiltinName> as Decode>::decode(input)
            .map_err(|e| e.chain("Could not decode `Program::builtins`"))?;

        Ok(Program {
            shared_program_data,
            constants,
            builtins,
        })
    }
}

impl Program {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        builtins: Vec<BuiltinName>,
        data: Vec<MaybeRelocatable>,
        main: Option<usize>,
        hints: HashMap<usize, Vec<HintParams>>,
        reference_manager: ReferenceManager,
        identifiers: HashMap<String, Identifier>,
        error_message_attributes: Vec<Attribute>,
        instruction_locations: Option<HashMap<usize, InstructionLocation>>,
    ) -> Result<Program, ProgramError> {
        let mut constants = HashMap::new();
        for (key, value) in identifiers.iter() {
            if value.type_.as_deref() == Some("const") {
                let value = value
                    .value
                    .clone()
                    .ok_or_else(|| ProgramError::ConstWithoutValue(key.clone()))?;
                constants.insert(key.clone(), value);
            }
        }
        let hints: BTreeMap<_, _> = hints.into_iter().collect();

        let (hints, hints_ranges) = Self::flatten_hints(&hints, data.len())?;

        let shared_program_data = SharedProgramData {
            data,
            main,
            start: None,
            end: None,
            hints,
            hints_ranges,
            error_message_attributes,
            instruction_locations,
            identifiers,
            reference_manager: Self::get_reference_list(&reference_manager),
        };
        Ok(Self {
            shared_program_data: Arc::new(shared_program_data),
            constants,
            builtins,
        })
    }

    pub(crate) fn flatten_hints(
        hints: &BTreeMap<usize, Vec<HintParams>>,
        program_length: usize,
    ) -> Result<(Vec<HintParams>, Vec<HintRange>), ProgramError> {
        let bounds = hints
            .iter()
            .map(|(pc, hs)| (*pc, hs.len()))
            .reduce(|(max_hint_pc, full_len), (pc, len)| (max_hint_pc.max(pc), full_len + len));

        let Some((max_hint_pc, full_len)) = bounds else {
            return Ok((Vec::new(), Vec::new()));
        };

        if max_hint_pc >= program_length {
            return Err(ProgramError::InvalidHintPc(max_hint_pc, program_length));
        }

        let mut hints_values = Vec::with_capacity(full_len);
        let mut hints_ranges = vec![None; max_hint_pc + 1];

        for (pc, hs) in hints.iter().filter(|(_, hs)| !hs.is_empty()) {
            let range = (
                hints_values.len(),
                NonZeroUsize::new(hs.len()).expect("empty vecs already filtered"),
            );
            hints_ranges[*pc] = Some(range);
            hints_values.extend_from_slice(&hs[..]);
        }

        Ok((hints_values, hints_ranges))
    }

    #[cfg(feature = "std")]
    pub fn from_file(path: &Path, entrypoint: Option<&str>) -> Result<Program, ProgramError> {
        let file_content = std::fs::read(path)?;
        deserialize_and_parse_program(&file_content, entrypoint)
    }

    pub fn from_bytes(bytes: &[u8], entrypoint: Option<&str>) -> Result<Program, ProgramError> {
        deserialize_and_parse_program(bytes, entrypoint)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let program_json: ProgramJson = parse_program(self.clone());
        serde_json::to_vec(&program_json).unwrap()
    }

    pub fn prime(&self) -> &str {
        _ = self;
        PRIME_STR
    }

    pub fn iter_builtins(&self) -> impl Iterator<Item = &BuiltinName> {
        self.builtins.iter()
    }

    pub fn iter_data(&self) -> impl Iterator<Item = &MaybeRelocatable> {
        self.shared_program_data.data.iter()
    }

    pub fn data_len(&self) -> usize {
        self.shared_program_data.data.len()
    }

    pub fn builtins_len(&self) -> usize {
        self.builtins.len()
    }

    pub fn get_identifier(&self, id: &str) -> Option<&Identifier> {
        self.shared_program_data.identifiers.get(id)
    }

    pub fn iter_identifiers(&self) -> impl Iterator<Item = (&str, &Identifier)> {
        self.shared_program_data
            .identifiers
            .iter()
            .map(|(cairo_type, identifier)| (cairo_type.as_str(), identifier))
    }

    pub(crate) fn get_reference_list(reference_manager: &ReferenceManager) -> Vec<HintReference> {
        reference_manager
            .references
            .iter()
            .map(|r| r.to_owned().into())
            .collect()
    }
}

impl Program {
    pub fn builtins(&self) -> &Vec<BuiltinName> {
        &self.builtins
    }

    pub fn data(&self) -> &Vec<MaybeRelocatable> {
        &self.shared_program_data.data
    }

    pub fn hints(&self) -> &Vec<HintParams> {
        &self.shared_program_data.hints
    }

    pub fn hints_ranges(&self) -> &Vec<HintRange> {
        &self.shared_program_data.hints_ranges
    }

    pub fn main(&self) -> &Option<usize> {
        &self.shared_program_data.main
    }

    pub fn start(&self) -> &Option<usize> {
        &self.shared_program_data.start
    }

    pub fn end(&self) -> &Option<usize> {
        &self.shared_program_data.end
    }

    pub fn error_message_attributes(&self) -> &Vec<Attribute> {
        &self.shared_program_data.error_message_attributes
    }

    pub fn instruction_locations(&self) -> &Option<HashMap<usize, InstructionLocation>> {
        &self.shared_program_data.instruction_locations
    }

    pub fn identifiers(&self) -> &HashMap<String, Identifier> {
        &self.shared_program_data.identifiers
    }

    pub fn constants(&self) -> &HashMap<String, Felt252> {
        &self.constants
    }

    pub fn reference_manager(&self) -> ReferenceManager {
        ReferenceManager {
            references: self
                .shared_program_data
                .reference_manager
                .iter()
                .map(|r| Reference {
                    value_address: ValueAddress {
                        offset1: r.offset1.clone(),
                        offset2: r.offset2.clone(),
                        dereference: r.dereference,
                        value_type: r.cairo_type.clone().unwrap_or_default(),
                    },
                    ap_tracking_data: r.ap_tracking_data.clone().unwrap_or_default(),
                    pc: r.pc,
                })
                .collect(),
        }
    }
}

impl Default for Program {
    fn default() -> Self {
        Self {
            shared_program_data: Arc::new(SharedProgramData::default()),
            constants: HashMap::new(),
            builtins: Vec::new(),
        }
    }
}

#[cfg(feature = "cairo-1-hints")]
// Note: This Program will only work when using run_from_entrypoint, and the Cairo1Hintprocesso
impl TryFrom<CasmContractClass> for Program {
    type Error = ProgramError;
    fn try_from(value: CasmContractClass) -> Result<Self, ProgramError> {
        let data = value
            .bytecode
            .iter()
            .map(|x| MaybeRelocatable::from(Felt252::from(x.value.clone())))
            .collect();
        //Hint data is going to be hosted processor-side, hints field will only store the pc where hints are located.
        // Only one pc will be stored, so the hint processor will be responsible for executing all hints for a given pc
        let hints = value
            .hints
            .iter()
            .map(|(x, _)| {
                (
                    *x,
                    vec![HintParams {
                        code: x.to_string(),
                        accessible_scopes: Vec::new(),
                        flow_tracking_data: FlowTrackingData {
                            ap_tracking: ApTracking::default(),
                            reference_ids: HashMap::new(),
                        },
                    }],
                )
            })
            .collect();
        let error_message_attributes = Vec::new();
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };
        Self::new(
            vec![],
            data,
            None,
            hints,
            reference_manager,
            HashMap::new(),
            error_message_attributes,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serde::deserialize_program::{ApTracking, FlowTrackingData};
    use crate::utils::test_utils::*;
    use felt::felt_str;
    use num_traits::Zero;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    #[cfg(feature = "parity-scale-codec")]
    fn test_encode_decode_program() {
        let program = Program::from_bytes(
            include_bytes!("../../../cairo_programs/manually_compiled/valid_program_a.json"),
            Some("main"),
        )
        .unwrap();

        assert_eq!(
            program,
            Program::decode(&mut &program.encode()[..]).unwrap()
        )
    }

    #[test]
    fn test_serialize_program() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let program = Program::new(
            builtins,
            data,
            None,
            HashMap::new(),
            reference_manager,
            HashMap::new(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(
            program,
            Program::from_bytes(&program.to_bytes(), None).unwrap()
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn new() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let program = Program::new(
            builtins.clone(),
            data.clone(),
            None,
            HashMap::new(),
            reference_manager,
            HashMap::new(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(program.builtins, builtins);
        assert_eq!(program.shared_program_data.data, data);
        assert_eq!(program.shared_program_data.main, None);
        assert_eq!(program.shared_program_data.identifiers, HashMap::new());
        assert_eq!(program.shared_program_data.hints, Vec::new());
        assert_eq!(program.shared_program_data.hints_ranges, Vec::new());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn new_program_with_hints() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let str_to_hint_param = |s: &str| HintParams {
            code: s.to_string(),
            accessible_scopes: vec![],
            flow_tracking_data: FlowTrackingData {
                ap_tracking: ApTracking {
                    group: 0,
                    offset: 0,
                },
                reference_ids: HashMap::new(),
            },
        };

        let hints = HashMap::from([
            (5, vec![str_to_hint_param("c"), str_to_hint_param("d")]),
            (1, vec![str_to_hint_param("a")]),
            (4, vec![str_to_hint_param("b")]),
        ]);

        let program = Program::new(
            builtins.clone(),
            data.clone(),
            None,
            hints.clone(),
            reference_manager,
            HashMap::new(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(program.builtins, builtins);
        assert_eq!(program.shared_program_data.data, data);
        assert_eq!(program.shared_program_data.main, None);
        assert_eq!(program.shared_program_data.identifiers, HashMap::new());

        let program_hints: HashMap<_, _> = program
            .shared_program_data
            .hints_ranges
            .iter()
            .enumerate()
            .filter_map(|(pc, r)| r.map(|(s, l)| (pc, (s, s + l.get()))))
            .map(|(pc, (s, e))| (pc, program.shared_program_data.hints[s..e].to_vec()))
            .collect();
        assert_eq!(program_hints, hints);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn new_program_with_identifiers() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();

        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: Some(Felt252::zero()),
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        let program = Program::new(
            builtins.clone(),
            data.clone(),
            None,
            HashMap::new(),
            reference_manager,
            identifiers.clone(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(program.builtins, builtins);
        assert_eq!(program.shared_program_data.data, data);
        assert_eq!(program.shared_program_data.main, None);
        assert_eq!(program.shared_program_data.identifiers, identifiers);
        assert_eq!(
            program.constants,
            [("__main__.main.SIZEOF_LOCALS", Felt252::zero())]
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect::<HashMap<_, _>>(),
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn get_prime() {
        let program = Program::default();
        assert_eq!(PRIME_STR, program.prime());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn iter_builtins() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<_> = vec![BuiltinName::range_check, BuiltinName::bitwise];
        let data: Vec<_> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let program = Program::new(
            builtins.clone(),
            data,
            None,
            HashMap::new(),
            reference_manager,
            HashMap::new(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(
            program.iter_builtins().cloned().collect::<Vec<_>>(),
            builtins
        );

        assert_eq!(program.builtins_len(), 2);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn iter_data() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let program = Program::new(
            builtins,
            data.clone(),
            None,
            HashMap::new(),
            reference_manager,
            HashMap::new(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(program.iter_data().cloned().collect::<Vec<_>>(), data);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn data_len() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let program = Program::new(
            builtins,
            data.clone(),
            None,
            HashMap::new(),
            reference_manager,
            HashMap::new(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(program.data_len(), data.len());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn get_identifier() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();

        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: Some(Felt252::zero()),
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        let program = Program::new(
            builtins,
            data,
            None,
            HashMap::new(),
            reference_manager,
            identifiers.clone(),
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(
            program.get_identifier("__main__.main"),
            identifiers.get("__main__.main"),
        );
        assert_eq!(
            program.get_identifier("__main__.main.SIZEOF_LOCALS"),
            identifiers.get("__main__.main.SIZEOF_LOCALS"),
        );
        assert_eq!(
            program.get_identifier("missing"),
            identifiers.get("missing"),
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn iter_identifiers() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();

        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                decorators: None,
                destination: None,
                references: None,
                size: None,
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
            },
        );

        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: Some(Felt252::zero()),
                decorators: None,
                destination: None,
                references: None,
                size: None,
                full_name: None,
                members: None,
                cairo_type: None,
            },
        );

        let program = Program::new(
            builtins,
            data,
            None,
            HashMap::new(),
            reference_manager,
            identifiers.clone(),
            Vec::new(),
            None,
        )
        .unwrap();

        let collected_identifiers: HashMap<_, _> = program
            .iter_identifiers()
            .map(|(cairo_type, identifier)| (cairo_type.to_string(), identifier.clone()))
            .collect();

        assert_eq!(collected_identifiers, identifiers);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn new_program_with_invalid_identifiers() {
        let reference_manager = ReferenceManager {
            references: Vec::new(),
        };

        let builtins: Vec<BuiltinName> = Vec::new();

        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        let program = Program::new(
            builtins,
            data,
            None,
            HashMap::new(),
            reference_manager,
            identifiers.clone(),
            Vec::new(),
            None,
        );

        assert!(program.is_err());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn deserialize_program_test() {
        let program = Program::from_bytes(
            include_bytes!("../../../cairo_programs/manually_compiled/valid_program_a.json"),
            Some("main"),
        )
        .unwrap();

        let builtins: Vec<BuiltinName> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: Some(vec![]),
                size: None,
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.Args"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Args".to_string()),
                members: Some(HashMap::new()),
                cairo_type: None,
                decorators: None,
                size: Some(0),
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.ImplicitArgs"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.ImplicitArgs".to_string()),
                members: Some(HashMap::new()),
                cairo_type: None,
                decorators: None,
                size: Some(0),
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.Return"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Return".to_string()),
                members: Some(HashMap::new()),
                cairo_type: None,
                decorators: None,
                size: Some(0),
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: Some(Felt252::zero()),
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        assert_eq!(program.builtins, builtins);
        assert_eq!(program.shared_program_data.data, data);
        assert_eq!(program.shared_program_data.main, Some(0));
        assert_eq!(program.shared_program_data.identifiers, identifiers);
    }

    /// Deserialize a program without an entrypoint.
    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn deserialize_program_without_entrypoint_test() {
        let program = Program::from_bytes(
            include_bytes!("../../../cairo_programs/manually_compiled/valid_program_a.json"),
            None,
        )
        .unwrap();

        let builtins: Vec<BuiltinName> = Vec::new();

        let error_message_attributes: Vec<Attribute> = vec![Attribute {
            name: String::from("error_message"),
            start_pc: 379,
            end_pc: 381,
            value: String::from("SafeUint256: addition overflow"),
            flow_tracking_data: Some(FlowTrackingData {
                ap_tracking: ApTracking {
                    group: 14,
                    offset: 35,
                },
                reference_ids: HashMap::new(),
            }),
            accessible_scopes: vec![
                "openzeppelin.security.safemath.library".to_string(),
                "openzeppelin.security.safemath.library.SafeUint256".to_string(),
                "openzeppelin.security.safemath.library.SafeUint256.add".to_string(),
            ],
        }];

        let data: Vec<MaybeRelocatable> = vec![
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(1000),
            mayberelocatable!(5189976364521848832),
            mayberelocatable!(2000),
            mayberelocatable!(5201798304953696256),
            mayberelocatable!(2345108766317314046),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                value: None,
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: Some(vec![]),
                size: None,
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.Args"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Args".to_string()),
                members: Some(HashMap::new()),
                cairo_type: None,
                decorators: None,
                size: Some(0),
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.ImplicitArgs"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.ImplicitArgs".to_string()),
                members: Some(HashMap::new()),
                cairo_type: None,
                decorators: None,
                size: Some(0),
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.Return"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Return".to_string()),
                members: Some(HashMap::new()),
                cairo_type: None,
                decorators: None,
                size: Some(0),
                destination: None,
                references: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: Some(Felt252::zero()),
                full_name: None,
                members: None,
                cairo_type: None,
                decorators: None,
                size: None,
                destination: None,
                references: None,
            },
        );

        assert_eq!(program.builtins, builtins);
        assert_eq!(program.shared_program_data.data, data);
        assert_eq!(program.shared_program_data.main, None);
        assert_eq!(program.shared_program_data.identifiers, identifiers);
        assert_eq!(
            program.shared_program_data.error_message_attributes,
            error_message_attributes
        )
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn deserialize_program_constants_test() {
        let program = Program::from_bytes(
            include_bytes!(
                "../../../cairo_programs/manually_compiled/deserialize_constant_test.json"
            ),
            Some("main"),
        )
        .unwrap();

        let constants = [
            ("__main__.compare_abs_arrays.SIZEOF_LOCALS", Felt252::zero()),
            (
                "starkware.cairo.common.cairo_keccak.packed_keccak.ALL_ONES",
                felt_str!(
                    "3618502788666131106986593281521497120414687020801267626233049500247285301247"
                ),
            ),
            (
                "starkware.cairo.common.cairo_keccak.packed_keccak.BLOCK_SIZE",
                Felt252::new(3),
            ),
            (
                "starkware.cairo.common.alloc.alloc.SIZEOF_LOCALS",
                felt_str!(
                    "-3618502788666131213697322783095070105623107215331596699973092056135872020481"
                ),
            ),
            (
                "starkware.cairo.common.uint256.SHIFT",
                felt_str!("340282366920938463463374607431768211456"),
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<HashMap<_, _>>();

        assert_eq!(program.constants, constants);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn default_program() {
        let shared_program_data = SharedProgramData {
            data: Vec::new(),
            hints: Vec::new(),
            hints_ranges: Vec::new(),
            main: None,
            start: None,
            end: None,
            error_message_attributes: Vec::new(),
            instruction_locations: None,
            identifiers: HashMap::new(),
            reference_manager: Program::get_reference_list(&ReferenceManager {
                references: Vec::new(),
            }),
        };
        let program = Program {
            shared_program_data: Arc::new(shared_program_data),
            constants: HashMap::new(),
            builtins: Vec::new(),
        };

        assert_eq!(program, Program::default());
    }
}
