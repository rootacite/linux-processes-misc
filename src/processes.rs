
// processes.rs

use std::collections::HashMap;
use std::fs;

use anyhow::Context;
use nix::sys::uio::{process_vm_readv, RemoteIoVec, process_vm_writev};
use nix::unistd::Pid;
use std::error::Error;

use std::io::{IoSliceMut, IoSlice};
use goblin::elf64::{header, section_header};
use iced_x86::code_asm::{r10, r8, r9, rax, rdi, rdx, rsi};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock};

use nix::sys::ptrace;
use libc::{user_regs_struct};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use crate::asm::{assemble, InstructionFormat};
use crate::elf::ExecuteLinkFile;
use crate::map::{MemoryMap};


const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

fn list_processes() -> Result<HashMap<String, i32>, std::io::Error>
{
    let mut processes = HashMap::<String, i32>::new();

    let entries = fs::read_dir("/proc")?;
    let dirs = entries.filter_map(|e| {
        let e = e.ok()?;
        let path = e.path();
        if path.is_dir() {
            return path.file_name()?.to_str().map(|s| s.to_string());
        }
        None::<String>
    }).collect::<Vec<String>>();

    for dir in dirs {
        let Ok(pid) = dir.parse::<i32>() else { continue };
        let pid_path = format!("/proc/{}/exe", dir);
        let Ok(name_path) = fs::read_link(&pid_path) else { continue };
        let name_path = name_path.to_string_lossy().to_string();

        if let Some(name) = name_path.split("/").last() {
            processes.insert(name.to_string(), pid);
        }
    }

    Ok(processes)
}

pub fn get_pid_by_name(name: &str) -> Result<i32, std::io::Error>
{
    let ps = list_processes()?;
    Ok(ps[name])
}

pub struct Process
{
    pid: Pid,
    map: MemoryMap,
}

impl Process
{
    fn write_unaligned_head(
        pid: Pid,
        addr: usize,
        data: &[u8],
        word_size: usize,
    ) -> Result<usize, Box<dyn Error>>
    {
        let head_offset = addr % word_size;
        let aligned_addr = addr - head_offset;
        let orig_word = ptrace::read(pid, aligned_addr as *mut libc::c_void)?;
        let mut bytes = orig_word.to_ne_bytes();

        let copy_len = usize::min(word_size - head_offset, data.len());
        bytes[head_offset..head_offset + copy_len].copy_from_slice(&data[..copy_len]);
        let new_word = libc::c_long::from_le_bytes(bytes);

        ptrace::write(pid, aligned_addr as *mut libc::c_void, new_word)?;
        Ok(copy_len)
    }

    fn write_full_word(
        pid: Pid,
        addr: usize,
        data: &[u8]
    ) -> Result<usize, Box<dyn Error>>
    {
        let mut arr = [0u8; size_of::<libc::c_long>()];
        arr.copy_from_slice(data);
        let val = libc::c_long::from_le_bytes(arr);
        ptrace::write(pid, addr as *mut libc::c_void, val)?;
        Ok(size_of::<libc::c_long>())
    }

    fn write_unaligned_tail(
        pid: Pid,
        addr: usize,
        data: &[u8],
        _word_size: usize,
    ) -> Result<usize, Box<dyn Error>>
    {
        let orig_word = ptrace::read(pid, addr as *mut libc::c_void)?;
        let mut bytes = orig_word.to_ne_bytes();
        bytes[..data.len()].copy_from_slice(data);
        let new_word = libc::c_long::from_le_bytes(bytes);

        ptrace::write(pid, addr as *mut libc::c_void, new_word)?;
        Ok(data.len())
    }

    pub fn new(pid: Pid) -> Result<Self, Box<dyn Error>>
    {
        let maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;
        let map = MemoryMap::new(&maps.lines().filter(|&line| !line.is_empty()).collect::<Vec<&str>>());

        Ok(Self { pid, map, })
    }

    pub fn wait(&self) -> Option<WaitStatus>
    {
        let f = waitpid(self.pid, Some(WaitPidFlag::WUNTRACED)).ok()?;

        match f {
            WaitStatus::Stopped(stopped_pid, signal) => {
                println!("[DEBUG] PID {} stopped by signal: {:?}", stopped_pid, signal);
            }
            WaitStatus::Exited(exited_pid, status) => {
                println!("[DEBUG] PID {} exited with status: {}", exited_pid, status);
            }
            WaitStatus::Signaled(signaled_pid, signal, core_dump) => {
                println!("[DEBUG] PID {} killed by signal: {:?} (core dump: {})",
                         signaled_pid, signal, core_dump);
            }
            WaitStatus::Continued(continued_pid) => {
                println!("[DEBUG] PID {} continued", continued_pid);
            }
            WaitStatus::StillAlive => {
                println!("[DEBUG] PID {} still alive", self.pid);
            }
            _ => {}
        }

        Some(f)
    }

    #[allow(unused)]
    pub fn get_pid(&self) -> Pid { self.pid.clone() }

    pub fn get_exe(&self) -> Result<String, Box<dyn Error>>
    {
        let r = fs::read_link(format!("/proc/{}/exe", self.pid))?
            .to_string_lossy()
            .into_owned();

        Ok(r)
    }

    pub fn get_map_str(&self) -> Result<String, Box<dyn Error>>
    {
        let r = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;

        Ok(r)
    }

    pub fn read_memory_vm(&self, start_addr: usize, size: usize) -> Result<Vec<u8>, Box<dyn Error>>
    {
        let mut buffer = vec![0u8; size];

        let mut local_iov = [IoSliceMut::new(&mut buffer)];

        let remote_iov = [RemoteIoVec {
            base: start_addr,
            len: size,
        }];

        let bytes_read = process_vm_readv(self.pid, &mut local_iov, &remote_iov)?;

        if bytes_read == size {
            Ok(buffer)
        } else {
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    #[allow(unused)]
    pub fn write_memory_vm(&self, mut start_addr: usize, mut data: &[u8]) -> Result<usize, Box<dyn Error>>
    {
        let mut total_written = 0usize;
        while !data.is_empty() {
            let local_iov = [IoSlice::new(data)];
            let remote_iov = [RemoteIoVec {
                base: start_addr,
                len: data.len(),
            }];

            let written = process_vm_writev(self.pid, &local_iov, &remote_iov)?;

            if written == 0 {
                return Err(format!("process_vm_writev returned 0 (no progress) after writing {} bytes", total_written).into());
            }

            total_written += written;
            start_addr = start_addr.wrapping_add(written);
            data = &data[written..];
        }

        Ok(total_written)
    }

    pub fn write_memory_ptrace(&self, start_addr: usize, data: &[u8]) -> Result<usize, Box<dyn Error>>
    {
        let word_size = size_of::<libc::c_long>();
        if word_size == 0 {
            return Err("invalid word size".into());
        }

        let mut addr = start_addr;
        let mut remaining = data;
        let mut written = 0usize;

        if addr % word_size != 0 && !remaining.is_empty() {
            let n = Self::write_unaligned_head(self.pid, addr, remaining, word_size)?;
            addr += n;
            remaining = &remaining[n..];
            written += n;
        }

        while remaining.len() >= word_size {
            let n = Self::write_full_word(self.pid, addr, &remaining[..word_size])?;
            addr += n;
            remaining = &remaining[n..];
            written += n;
        }

        if !remaining.is_empty() {
            let n = Self::write_unaligned_tail(self.pid, addr, remaining, word_size)?;
            written += n;
        }

        Ok(written)
    }

    #[allow(unused)]
    pub fn find_remote_proc(
        &self,
        module: &str,  // Full path of module, like '/usr/lib/libc.so.6'
        symbol: &str  // Symbol name, like 'printf'
    ) -> Option<u64>
    {
        let elf = ExecuteLinkFile::prase(module).ok()?;
        let sym = elf.prase_dyn_sym(symbol).ok()?;

        let target_maps = fs::read_to_string(format!("/proc/{}/maps", self.pid)).ok()?;
        let base = MemoryMap::new(&target_maps.lines().collect::<Vec<&str>>()).module_base_address(module)?;

        let is_undefined = sym.st_shndx == section_header::SHN_UNDEF as usize;

        if !is_undefined && sym.st_value != 0 {
            return if elf.get_e_type() == header::ET_DYN {
                Some(base + sym.st_value)
            } else {
                // ET_EXEC or others: assume st_value is absolute
                Some(sym.st_value)
            }
        }

        None
    }

    pub fn find_got_pointer_plt(&self, symbol: &str) -> Option<u64>
    {
        let exe = self.get_exe().ok()?;
        let elf = ExecuteLinkFile::prase(&exe).ok()?;

        let r_sym = elf.get_rela_sym(symbol).ok()?;
        Some(r_sym.r_offset + self.map.module_base_address(&exe)?)
    }

    pub fn execute_once_inplace<F, F2>(
        &self, 
        payload_builder: F,
        post_proc: F2
    ) 
        -> Result<user_regs_struct, Box<dyn Error>>
        where F: Fn(u64) -> Option<Vec<u8>>, F2: Fn(&user_regs_struct) -> Result<(), Box<dyn Error>>
    {
        // Save context
        let regs = ptrace::getregs(self.pid)?;
        let payload = payload_builder(regs.rip).context("payload build failed")?;

        let buffer = self.read_memory_vm(regs.rip as usize, payload.len() + 1)?;
        let instruction = [&payload as &[u8], &[0xccu8]].concat();

        self.write_memory_ptrace(regs.rip as usize, &instruction)?;
        println!("{GREEN}[trace]{RESET} write instructions to {:#016x}", regs.rip);

        self.disassemble(regs.rip, (instruction.len()) as u64, |inst| {
            for i in inst.iter() {
                println!("{GREEN}[disassemble]{RESET} {YELLOW}{}{RESET}", i.fmt_line_default()?);
            }

            Ok(())
        })?;

        // Continue target
        ptrace::cont(self.pid, None)?;
        println!("{GREEN}[trace]{RESET} continue from {:#016x}", regs.rip);
        self.wait();

        let r = ptrace::getregs(self.pid)?;
        println!("{GREEN}[trace]{RESET} int3 at {:#016x}", r.rip);

        post_proc(&r)?;

        self.write_memory_ptrace(regs.rip as usize, &buffer)?;
        ptrace::setregs(self.pid, regs)?;
        Ok(r)
    }

    pub fn alloc_pages(&self, count: u64, permissions: u64)
        -> Result<u64, Box<dyn Error>>
    {
        // Alloc r-x private memory
        let r = self.execute_once_inplace(|addr| {
            let r = assemble(addr, |asm| {
                asm.mov(rax, 9u64)?; // Syscall 9 (mmap)

                asm.mov(rdi, 0u64)?; // Addr
                asm.mov(rsi, 0x1000u64 * count)?; // Length, we alloc a page (4K)
                asm.mov(rdx, permissions, )?;
                asm.mov(r10, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64)?; // Private and anonymous
                asm.mov(r8, -1i64)?; // Fd (-1 because we want anonymous)
                asm.mov(r9, 0u64)?; // Offset

                asm.syscall()?; // Syscall interrupt
                Ok(())
            }).ok()?;

            Some(r)
        }, |_| { Ok(()) })?;

        Ok(r.rax as u64)
    }

    pub fn disassemble<F, T>(
        &self,
        addr: u64,
        size: u64,
        callback: F,
    ) -> Result<T, Box<dyn Error>>
    where
        F: Fn(&[Instruction]) -> Result<T, Box<dyn Error>>,
    {
        let code_bytes = self.read_memory_vm(addr as usize, size as usize)?;
        let decoder = Decoder::with_ip(64, &code_bytes, addr, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        let result = callback(&instructions)?;
        Ok(result)
    }


    pub fn instruction_relocate(&self, addr: u64, size: u64, new_addr: u64)
                                -> Result<Vec<u8>, Box<dyn Error>>
    {
        let origin = self.read_memory_vm(addr as usize, size as usize)?;

        let decoder = Decoder::with_ip(64, &origin, addr, DecoderOptions::NONE);
        let instructions: Vec<_> = decoder.into_iter().collect();

        let block = InstructionBlock::new(&instructions, new_addr);
        let options = BlockEncoderOptions::RETURN_RELOC_INFOS;

        let result = BlockEncoder::encode(64, block, options)
            .map_err(|e| format!("BlockEncoder failed: {}", e))?;

        Ok(result.code_buffer.clone())
    }
}
