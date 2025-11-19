
// map.rs

use crate::elf::ExecuteLinkFile;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_addr: u64,
    pub end_addr: u64,
    pub perms: String,
    pub offset: Option<u64>,
    pub dev: Option<String>,
    pub inode: Option<u64>,
    pub pathname: Option<String>,
}

impl MemoryRegion {
    pub fn parse(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let range_part = parts[0];
        let range_parts: Vec<&str> = range_part.split('-').collect();
        if range_parts.len() != 2 {
            return None;
        }
        let start_addr = u64::from_str_radix(range_parts[0], 16).ok()?;
        let end_addr = u64::from_str_radix(range_parts[1], 16).ok()?;

        let perms = parts[1].to_string();

        let offset = parts.get(2).and_then(|s| u64::from_str_radix(s, 16).ok());
        let dev = parts.get(3).map(|s| s.to_string());
        let inode = parts.get(4).and_then(|s| s.parse::<u64>().ok());
        let pathname = parts.get(5).map(|s| s.to_string());

        Some(Self {
            start_addr,
            end_addr,
            perms,
            offset,
            dev,
            inode,
            pathname,
        })
    }

    pub fn is_read_write(&self) -> bool {
        self.perms.starts_with("rw")
    }

    pub fn is_executable(&self) -> bool {
        self.perms.contains('x')
    }
}

#[derive(Debug)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    pub fn new(lines: &Vec<&str>) -> Self {
        let regions = lines
            .iter()
            .filter_map(|line| MemoryRegion::parse(line))
            .collect();
        Self { regions }
    }

    #[allow(unused)]
    pub fn first_rw_segment(&self, module: &str) -> Option<(u64, u64)> {
        self.regions
            .iter()
            .find(|r| r.is_read_write() && r.pathname.as_deref() == Some(module))
            .map(|r| (r.start_addr, r.end_addr))
    }

    #[allow(unused)]
    pub fn first_exec_segment(&self, module: &str) -> Option<(u64, u64)> {
        self.regions
            .iter()
            .find(|r| r.is_executable() && r.pathname.as_deref() == Some(module))
            .map(|r| (r.start_addr, r.end_addr))
    }

    #[allow(unused)]
    pub fn module_base_address(
        &self,
        module: &str // Full path of module, like '/usr/lib/libc.so.6'
    ) -> Option<u64> {
        let elf = ExecuteLinkFile::prase(&module).ok()?;
        let loads = elf.get_loads().ok()?;
        let Some(first_load) = loads.iter().find(|p| {
            p.is_executable()
        }) else {
            return None;
        };

        let Some(map_item) = self.regions.iter().find(|r| {
            r.offset.unwrap_or(0) == first_load.p_offset && r.pathname.as_deref() == Some(module) && r.is_executable()
        }) else {
            return None;
        };

        Some(map_item.start_addr - first_load.p_vaddr)
    }

    #[allow(unused)]
    pub fn collect_module(&self, module: &str) -> Vec<MemoryRegion>
    {
        let r = self.regions.iter()
            .filter_map(|r| if r.pathname.as_deref() == Some(module) { Some(r.clone()) } else { None })
            .collect::<Vec<MemoryRegion>>();

        r
    }
}
