use std::error::Error;
use std::ffi::CString;
use std::thread;
use std::time::Duration;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::Pid;
use crate::asm::assemble;
use crate::processes::Process;
use iced_x86::code_asm::*;
use libc::{sleep, usleep};

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

// Process Hollowing

#[allow(unused)]
pub fn shell_hollowing<F>(
    proc: &Process,
    seg_rw: (u64, u64),
    payload: F
) -> Result<i32, Box<dyn Error>>
where
    F: Fn(&Process, u64, u64) -> Result<Vec<u8>, Box<dyn Error>>,
{
    let regs = ptrace::getregs(proc.get_pid())?;


    Ok(0)
}

#[allow(unused)]
pub fn thread_injecting<F>(
    proc: &Process,
    payload: F
) -> Result<i32, Box<dyn Error>>
where
    F: Fn(&Process, u64) -> Result<Vec<u8>, Box<dyn Error>>,
{
    // Alloc rwx memory
    let page_addr = proc.alloc_pages(1, (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64)? as usize;

    println!(
        "{GREEN}[trace]{RESET} allocated page is at {:#016x}",
        page_addr
    );

    let injected_data = "[%d] I am the injected thread, I am running... \r\n";
    proc.write_memory_vm(
        page_addr + 0x200,
        &CString::new(injected_data).unwrap().as_bytes_with_nul(),
    )?;
    proc.write_memory_vm(page_addr + 0x300, &1i64.to_le_bytes())?;
    proc.write_memory_vm(page_addr + 0x308, &0u64.to_le_bytes())?;


    // Construct inject payload
    proc.write_memory_vm(page_addr, &payload(proc, page_addr as u64)?)?;
    println!("{GREEN}[trace]{RESET} write payload to {:#016x}", page_addr);

    // Start Trigger
    let rp = proc.execute_once_inplace(|addr| {
        let r = assemble(addr, |asm| {
            asm.mov(rax, 56u64)?; // Syscall 56 (clone)

            asm.mov(
                rdi,
                (libc::CLONE_VM
                    | libc::CLONE_FS
                    | libc::CLONE_FILES
                    | libc::CLONE_SIGHAND
                    | libc::CLONE_THREAD) as u64,
            )?; // Flags
            asm.mov(rsi, (page_addr + 0x1000) as u64)?; // Stack top

            asm.mov(rdx, 0u64)?; // parent_tid = NULL
            asm.mov(r10, 0u64)?; // child_tid = NULL
            asm.mov(r8, 0u64)?; // tls = NULL

            asm.syscall()?; // Syscall interrupt
            asm.test(eax, eax)?; // Syscall returns zero?
            asm.jz(page_addr as u64)?;
            asm.int3()?;
            Ok(())
        }).ok()?;

        Some(r)
    }, |post_regs| {
        let pid_new_thread = Pid::from_raw(post_regs.rax as i32);
        println!(
            "{GREEN}[trace]{RESET} new thread is {}.",
            pid_new_thread
        );

        ptrace::attach(pid_new_thread)?;
        waitpid(pid_new_thread, Some(WaitPidFlag::WUNTRACED))?;
        println!("{GREEN}[trace]{RESET} attached new thread.");

        loop {
            let regs = ptrace::getregs(pid_new_thread)?;
            println!(
                "{GREEN}[trace]{RESET} rip in new thread is {:#016x}.",
                regs.rip
            );

            if regs.rip >= page_addr as u64 && regs.rip < (page_addr + 0x1000) as u64 {
                println!("{GREEN}[trace]{RESET} rip in new thread return to inject payload.");
                break Ok(());
            }

            ptrace::step(pid_new_thread, None)?;
            waitpid(pid_new_thread, Some(WaitPidFlag::WUNTRACED))?;
        }
    })?.rax;

    Ok(rp as i32)
}