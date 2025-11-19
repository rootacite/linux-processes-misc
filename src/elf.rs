
// elf.rs

use anyhow::{Context};
use goblin::elf::{Elf, ProgramHeader, Sym, program_header::PT_DYNAMIC, program_header::PT_LOAD, reloc::R_X86_64_JUMP_SLOT, Reloc};
use memmap2::Mmap;
use std::fs::File;
use std::ops::Deref;
use ouroboros::self_referencing;

fn open_mem_map(path: &str) -> Result<Mmap, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    unsafe { Ok(Mmap::map(&file)?) }
}

#[self_referencing]
pub struct ExecuteLinkFile {
    data: Vec<u8>,

    #[borrows(data)]
    #[covariant]
    elf: Elf<'this>
}

impl ExecuteLinkFile {
    pub fn prase(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = open_mem_map(path)?.deref().to_owned();
        let s = ExecuteLinkFileTryBuilder {
            data,
            elf_builder: |data_ref| {
                Elf::parse(&data_ref)
            }
        }.try_build()?;

        Ok(s)
    }

    pub fn get_loads(&self) -> Result<Vec<ProgramHeader>, Box<dyn std::error::Error>> {
        let loads = self.borrow_elf()
            .program_headers
            .iter()
            .filter_map(|ph| match ph.p_type {
                PT_LOAD => Some(ph.to_owned()),
                _ => None,
            })
            .collect::<Vec<ProgramHeader>>();

        Ok(loads)
    }

    #[allow(unused)]
    pub fn get_dynamic(&self) -> Result<ProgramHeader, Box<dyn std::error::Error>> {
        let dynamic = self.borrow_elf()
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_DYNAMIC)
            .context("No PT_DYNAMIC segment found")?;

        Ok(dynamic.clone())
    }

    pub fn get_rela_sym(&self, name: &str) -> Result<Reloc, Box<dyn std::error::Error>> {
        let rela_plt = self.borrow_elf().pltrelocs.iter();

        let sym = rela_plt
            .filter(|rela| {
                matches!(rela.r_type, R_X86_64_JUMP_SLOT) // R_X86_64_JUMP_SLOT
            })
            .filter_map(|rela| {
                let sym_index = rela.r_sym;
                let Ok(sym) = self.get_dyn_sym(sym_index) else {
                    return None;
                };
                let Ok(sym_name) = self.get_dyn_str(sym.st_name) else {
                    return None;
                };

                if sym_name == name { Some(rela) } else { None }
            })
            .collect::<Vec<Reloc>>();

        let first = sym
            .first()
            .context(format!("No symbol found with name {}", name))?;

        Ok(first.clone())
    }

    pub fn get_dyn_sym(&self, location: usize) -> Result<Sym, Box<dyn std::error::Error>> {
        let dyn_sym = self.borrow_elf()
            .dynsyms
            .get(location)
            .context(format!("No symbol found at location {}", location))?;

        Ok(dyn_sym.clone())
    }

    #[allow(unused)]
    pub fn prase_dyn_sym(&self, name: &str) -> Result<Sym, Box<dyn std::error::Error>> {
        let dyn_sym = self.borrow_elf()
            .dynsyms.iter()
            .find(|sym| self.get_dyn_str(sym.st_name).ok().as_deref() == Some(name))
            .context(format!("No symbol found with name {}", name))?;

        Ok(dyn_sym.clone())
    }

    pub fn get_dyn_str(&self, location: usize) -> Result<String, Box<dyn std::error::Error>> {
        let str = self.borrow_elf()
            .dynstrtab
            .get_at(location)
            .context(format!("Could not get dynstr at location {}", location))?;

        Ok(str.to_owned())
    }
    
    #[allow(unused)]
    pub fn get_e_type(&self) -> u16
    {
        self.borrow_elf().header.e_type
    }
}
