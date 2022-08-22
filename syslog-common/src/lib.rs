#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysCallLog {
    pub ts            : u64,
    pub syscall       : u64,
    pub pid           : u64,
    pub pname_bytes   : [u8; 16]
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SysCallLog{} // 
