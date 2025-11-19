
// asm.rs

use std::error::Error;
use iced_x86::{code_asm::*, Formatter, Instruction, NasmFormatter};

pub fn assemble<F>(addr: u64, op: F) -> Result<Vec<u8>, Box<dyn Error>>
where
    F: Fn(&mut CodeAssembler) -> Result<(), Box<dyn Error>>,
{
    let mut asm = CodeAssembler::new(64)?;
    _ = op(&mut asm);
    Ok(asm.assemble(addr)?)
}

pub trait InstructionFormat {
    fn fmt_line(&self, formatter: &mut dyn Formatter) -> Result<String, Box<dyn Error>>;
    fn fmt_line_default(&self) -> Result<String, Box<dyn Error>>;
}

impl InstructionFormat for Instruction {
    fn fmt_line(&self, formatter: &mut dyn Formatter) -> Result<String, Box<dyn Error>> {
        let mut asm_str = String::new();
        formatter.format(self, &mut asm_str);

        Ok(format!(
            "{:#016x}[{:02}] {}",
            self.ip(),
            self.len(),
            asm_str
        ))
    }

    fn fmt_line_default(&self) -> Result<String, Box<dyn Error>> {
        let mut fmt = NasmFormatter::new();
        self.fmt_line(&mut fmt)
    }
}