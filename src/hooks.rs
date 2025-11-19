
// hooks.rs

use std::error::Error;

use crate::map::MemoryMap;
use crate::processes::Process;
use anyhow::Context;

use crate::asm::{assemble, InstructionFormat};

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

#[allow(unused)]
pub fn plt_hook<F>(
    proc: &Process,
    map: &MemoryMap,
    symbol: &str,
    payload: F,
) -> Result<(), Box<dyn Error>>
where
    F: Fn(&Process, u64, u64) -> Result<Vec<u8>, Box<dyn Error>>,
{
    let bias = map.module_base_address(&proc.get_exe()?).unwrap_or(0);
    let got_item_ptr = proc
        .find_got_pointer_plt(symbol)
        .context("Unable to find symbol")?;

    println!("{GREEN}[memory map]{RESET} Bias is {:#016x}", bias);

    let got_item_byte: [u8; 8] = proc
        .read_memory_vm(got_item_ptr as usize, 8)?
        .try_into()
        .map_err(|_| "Failed to convert Vec to array")?;
    let got_item = u64::from_le_bytes(got_item_byte);
    println!("{GREEN}[memory map]{RESET} got_item = {:#016x}", got_item);

    let page_addr = proc.alloc_pages(1, (libc::PROT_READ | libc::PROT_EXEC) as u64)?;
    println!(
        "{GREEN}[plt hook]{RESET} allocated page is at {:#016x}",
        page_addr
    );

    let payload = payload(&proc, page_addr, got_item)?;
    if payload.len() > 0x1000 {
        return Err(Box::<dyn Error>::from("payload exceeds 0x1000 bytes"));
    }

    proc.write_memory_ptrace(page_addr as usize, &payload)?;
    println!(
        "{GREEN}[plt hook]{RESET} wrote {} bytes of instructions/data to {:#016x}",
        payload.len(),
        page_addr
    );
    proc.write_memory_ptrace(got_item_ptr as usize, &page_addr.to_le_bytes())?;
    println!(
        "{GREEN}[plt hook]{RESET} rewrote got item at {:#016x} to {:#016x}, old value is {:#016x}",
        got_item_ptr, page_addr, got_item
    );

    Ok(())
}

#[allow(unused)]
pub fn inline_hook<F>(
    proc: &Process,
    module: &str,
    symbol: &str,
    payload: F, // With stdcall, the payload has to clean the stack. But that's uncommon.
) -> Result<(), Box<dyn Error>>
where
    F: Fn(&Process, u64, u64) -> Result<Vec<u8>, Box<dyn Error>>,
{
    let remote_addr = proc.find_remote_proc(module, symbol).context("Unable to find proc")?;

    println!("{GREEN}[memory map]{RESET} remote proc addr = {:#016x}", remote_addr);

    let page_addr = proc.alloc_pages(2, (libc::PROT_READ | libc::PROT_EXEC) as u64)?;
    println!(
        "{GREEN}[inline hook]{RESET} allocated page is at {:#016x}",
        page_addr
    );

    let payload_addr = page_addr + 32;
    let gateway_addr = page_addr;

    let payload = payload(&proc, payload_addr, gateway_addr)?;
    if payload.len() > 0x2000 - 32 { return Err(Box::<dyn Error>::from("payload exceeds limit bytes")); }
    proc.write_memory_ptrace(payload_addr as usize, &payload)?;
    println!("{GREEN}[inline hook]{RESET} wrote payload to {:#016x}", payload_addr);

    let jmp_inst = assemble(remote_addr, |asm| {
        asm.jmp(payload_addr)?;
        Ok(())
    })?;

    let (gateway_sz, gap_sz) = proc.disassemble(remote_addr, 128, |inst| {
        let mut sum_inst_size = 0u32;

        for i in inst.iter() {
            println!("{GREEN}[disassemble]{RESET} {YELLOW}{}{RESET}", i.fmt_line_default()?);
            if (sum_inst_size as usize) < jmp_inst.len() {
                sum_inst_size += i.len() as u32;
            } else {
                break;
            }
        }

        if (sum_inst_size as usize) < jmp_inst.len() {
            return Err(Box::<dyn Error>::from(
                "Unable to find a suitable instruction boundary.",
            ));
        }

        let boundary = remote_addr + sum_inst_size as u64;

        // Moving instructions to other locations for execution is !NOT! always safe,
        // but for library functions, this usually works,
        // because the first few instructions are usually endbr64, push rbp or something like that.
        let mut gateway = proc.instruction_relocate(remote_addr, sum_inst_size as u64, gateway_addr)?;

        println!("{GREEN}[inline hook]{RESET} instruction boundary located at {:#016x}", boundary);

        gateway.append(&mut assemble(gateway_addr + gateway.len() as u64, |asm|{
            asm.jmp(boundary)?;
            Ok(())
        })?);

        proc.write_memory_ptrace(gateway_addr as usize, &gateway)?;
        println!("{GREEN}[inline hook]{RESET} {} bytes of gateway code write to {:#016x}",gateway.len(), gateway_addr);
        Ok((gateway.len(), sum_inst_size))
    })?;

    proc.disassemble(gateway_addr, gateway_sz as u64, |inst| {
        for i in inst.iter() {
            println!("{GREEN}[disassemble]{RESET} {YELLOW}{}{RESET}", i.fmt_line_default()?);
        }
        Ok(())
    })?;

    proc.write_memory_ptrace(remote_addr as usize, &vec![0x90u8; gap_sz as usize])?;
    proc.write_memory_ptrace(remote_addr as usize, &jmp_inst)?;

    println!("{GREEN}[inline hook]{RESET} wrote springboard to {:#016x}", remote_addr);

    proc.disassemble(remote_addr, gap_sz as u64, |inst| {
        for i in inst.iter() {
            println!("{GREEN}[disassemble]{RESET} {YELLOW}{}{RESET}", i.fmt_line_default()?);
        }
        Ok(())
    })?;

    proc.disassemble(remote_addr + gap_sz as u64, 32, |inst| {
        for i in inst.iter() {
            println!("{GREEN}[disassemble]{RESET} {YELLOW}{}{RESET}", i.fmt_line_default()?);
            break;
        }
        Ok(())
    })?;

    Ok(())
}
