use colored::Colorize;
use pairipcore::error::Error;

use crate::util::key::find_key_loc;
use crate::{util, FindKeyOptions};

pub fn main(options: &FindKeyOptions) -> Result<(), Error> {
    if let Some(vmcode_file) = &options.input.vmcode_file {
        println!("[{}]: {:#}", "filepath".bold(), vmcode_file.display());

        let data = std::fs::read(vmcode_file).unwrap();
        let mut context = pairipcore::ctx::Ctx::new(&data);

        let fmt_ids = util::get_format_ids_or_default(options.fmt_ids.as_ref());

        println!("[{}]: ({})", "formatids".bold(), fmt_ids.len());
        if fmt_ids.len() < 3 {
            println!(
                " {}",
                "More than three (3) formats are recommended".yellow()
            );
        }

        if let Ok(key_addr) = find_key_loc(&mut context, &fmt_ids) {
            println!("[{}]:", "key".green().bold());
            println!(" - offset: {:#x}", key_addr.unwrap());

            let data = context.slice(key_addr, 0xFF);
            println!(" - material: {}", hex::encode(data));

            if let Some(out_file_path) = &options.save_to {
                if options.as_bin {
                    std::fs::write(out_file_path, data)?;
                } else {
                    std::fs::write(out_file_path, hex::encode(data))?;
                }
            }
        } else {
            println!("{}", "UH OH, could not find key".red());
        }
    }
    Ok(())
}
