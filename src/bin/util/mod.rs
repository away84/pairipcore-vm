use pairipcore::insn::InstructionFormat;

pub mod key;
pub mod strings;

pub fn get_format_ids_or_default(formats: Option<&String>) -> Vec<InstructionFormat> {
    if let Some(fmt_ids) = formats {
        fmt_ids
            .split(',')
            .map(|s| InstructionFormat::parse(s))
            .collect()
    } else {
        itertools::iproduct!(1..=5, 0..=5)
            .map(|(l, e)| InstructionFormat::new(l, e, None))
            .collect()
    }
}
