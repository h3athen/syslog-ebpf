#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysCallLog {
    pub ts      : u64,
    pub syscall : u64,
    pub pid     : u32,
    pub pname   : &'static str, // &str with Static lifetime
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SysCallLog {} // 
