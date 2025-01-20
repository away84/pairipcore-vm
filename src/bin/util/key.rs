use std::collections::HashSet;

use pairipcore::{ctx::Ctx, error::Error, insn::InstructionFormat, PhysAddress};

use super::strings;

fn is_printable(c: char) -> bool {
    c.is_ascii_graphic()
}

pub fn find_key_loc<'d>(
    ctx: &mut Ctx<'d>,
    insn_formats: &[InstructionFormat],
) -> Result<PhysAddress, Error> {
    // first, reset context VIP
    ctx.vip = 0x08.into();

    // NOTE:
    // To find the key location, we traverse the whole vmcode file and
    // try to decode two valid strings. As we don't know which variable
    // will store the key, we need to store both, the data location and
    // key location.
    let mut candidates: HashSet<u32> = HashSet::new();

    let upper_bound = (ctx.data().len() - 2) as u32;
    while ctx.vip.unwrap() < upper_bound {
        // opcode will be skipped as it is useless now
        ctx.advance(2);

        // TODO: define custom formats
        let mut found = false;
        for format in insn_formats {
            // the instruction will store all relevant information for us:
            //  - variables
            //  - hash data length
            let insn = ctx.read_insn_at(ctx.vip, &format)?;

            // invalid hashes can be skipped
            if insn.hash_len < 2 || insn.hash_len > 6 {
                continue;
            }

            // try all possible combinations
            for key_var_idx in 0..format.var_count() {
                let key_addr = ctx.translate(insn.get_reg(key_var_idx));
                // key will be at most 0xFF bytes. Therefore we have to include
                // a bounds check
                if key_addr.unwrap() + 0xFF >= upper_bound {
                    // can't be a valid key
                    continue;
                }

                // will be used to decode string length later on
                let key_len = ctx.read_u16_at(key_addr) as u32;
                let key_data =
                    &ctx.data()[key_addr.unwrap() as usize..(key_addr.unwrap() + 0xFF) as usize];

                // now, we iterate over all data variables and try to decode a valid
                // PRINTABLE string
                for data_var_idx in 0..format.var_count() {
                    if data_var_idx == key_var_idx {
                        continue;
                    }

                    let data_addr = ctx.translate(insn.get_reg(data_var_idx));
                    if data_addr.unwrap() + 2 >= upper_bound {
                        // in some cases, the data variable may point to the end of the file
                        continue;
                    }

                    let data_len = ctx.read_u16_at(data_addr) as u32;
                    let length = (key_len ^ data_len) + 2;
                    if length > 1000 || length < 3 || (data_addr.unwrap() + length) >= upper_bound {
                        // Length must be at least 3 bytes (we will filter large strings out)
                        continue;
                    }

                    let us_data_addr = data_addr.unwrap() as usize;
                    let data = &ctx.data()[us_data_addr..us_data_addr + length as usize];

                    match strings::decode_str(data, key_data) {
                        Some(s) => {
                            // check if the string is printable
                            if s.chars().all(is_printable) && s.len() > 2 {
                                // great, lets check if the key has been previously recorded
                                if candidates.contains(key_addr.as_ref()) {
                                    return Ok(key_addr);
                                }

                                if candidates.contains(data_addr.as_ref()) {
                                    // key has been recorded before
                                    return Ok(data_addr);
                                }

                                candidates.insert(key_addr.unwrap());
                                candidates.insert(data_addr.unwrap());
                                found = true;
                                // we must advance here to reduce false positives
                                ctx.advance(insn.len() as u32);
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if found {
                    break;
                }
            }

            if found {
                break;
            }
        }
    }

    Err(Error::CustomError("Key not found".to_string()))
}
