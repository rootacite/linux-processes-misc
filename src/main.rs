
// main.rs

use std::error::Error;
use anyhow::Context;
use iced_x86::code_asm::*;
use crate::map::MemoryMap;
use crate::processes::{get_pid_by_name, Process};
use nix::unistd::Pid;
use libc::user_regs_struct;
use nix::sys::ptrace;
use crate::asm::assemble;

const GREEN: &str = "\x1b[32m";
const RESET: &str = "\x1b[0m";

mod elf;
mod map;
mod processes;
mod asm;
mod hooks;
mod shell_exec;

fn main() -> Result<(), Box<dyn Error>> {
    // Find our target program
    let pid = Pid::from_raw(get_pid_by_name("target")?);
    let process = Process::new(pid)?;

    let exe = process.get_exe()?;
    let maps = process.get_map_str()?;
    let lines: Vec<&str> = maps.lines().filter(|&line| !line.is_empty()).collect();

    for line in &lines {
        println!("{GREEN}[memory map]{RESET} {}", line);
    }

    let map = MemoryMap::new(&lines);

    let seg_x = map.first_exec_segment(&exe).context("Can't find first exec segment")?;

    ptrace::attach(pid)?;
    process.wait();
    ptrace::step(pid, None)?;
    process.wait();

    // Save context
    let regs = ptrace::getregs(pid)?; // Save current registers

    ptrace::setregs(
        pid,
        user_regs_struct {
            rip: seg_x.0,
            ..regs
        },
    )?;

    // Do inject here

    let x = shell_exec::thread_injecting(&process, |proc, addr| {
        let printf = proc.find_remote_proc("/usr/lib/libc.so.6", "printf").unwrap();

        let r = assemble(addr as u64, |asm| {
            let mut target_label = asm.create_label();

            asm.mov(rbp, rsp)?;
            asm.mov(rcx, 0u64)?;
            asm.set_label(&mut target_label)?;

            asm.add(rcx, 1i32)?;
            asm.push(rcx)?;

            asm.mov(rdi, (addr + 0x200) as u64)?;
            asm.mov(rsi, rcx)?;
            asm.call(printf)?;

            asm.mov(rax, 35u64)?; // Syscall 35 (nano sleep)
            asm.mov(rdi, (addr + 0x300) as u64)?; // Req
            asm.mov(rsi, 0u64)?; //Rem
            asm.syscall()?; // Syscall interrupt

            asm.pop(rcx)?;
            asm.jmp(target_label)?; // Jmp back to loop
            Ok(())

            /*
                equals:
                while(true){
                    printf()
                    nanosleep()
                }
            */
        })?;

        Ok(r)
    })?;
    // End inject logics

    // Restore context
    ptrace::setregs(pid, regs)?;
    ptrace::detach(pid, None)?;
    ptrace::detach(Pid::from_raw(x), None)?;
    
    Ok(())
}


/*
 hooks::inline_hook(&process, "/usr/lib/libc.so.6", "write", |_proc, addr, old| {
        let inst = assemble(addr, |asm| {
            asm.endbr64()?;
            asm.push(rdi)?;
            asm.push(rsi)?;
            asm.push(rdx)?;
            asm.mov(rdi, 1u64)?;
            asm.mov(rsi, addr + 0x800)?;
            asm.mov(rdx, 7u64)?;
            asm.call(old)?;
            asm.pop(rdx)?;
            asm.pop(rsi)?;
            asm.pop(rdi)?;

            asm.call(old)?;

            asm.mov(rdi, 1u64)?;
            asm.mov(rsi, addr + 0x810)?;
            asm.mov(rdx, 2u64)?;
            asm.call(old)?;

            asm.ret()?;
            Ok(())
        }).unwrap();

        let mut payload = Vec::from([0u8; 0x1000]);
        payload.splice(0..inst.len(), inst);
        payload.splice(0x800..(0x800 + 7), Vec::from("[hook] ".as_bytes()));
        payload.splice(0x810..(0x810 + 2), Vec::from("\r\n".as_bytes()));

        Ok(payload)
    })?;
*/