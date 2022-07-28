#![no_std]
#![no_main]

use core::slice;

use aya_bpf::{
    helpers::bpf_ktime_get_ns,
    macros::tracepoint,
    programs::TracePointContext, BpfContext,
};
use aya_log_ebpf::info;

#[tracepoint(name="syslog")]
pub fn syslog(ctx: TracePointContext) -> u32 {
    match unsafe { try_syslog(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_syslog(ctx: TracePointContext) -> Result<u32, u32> {
    // Parsing the arguments from raw_syscalls/sys_enter
    let args = slice::from_raw_parts(ctx.as_ptr() as *const usize, 2);
    
/*
u64 bpf_ktime_get_ns(void)

              Description
                     Return the time elapsed since system boot, in
                     nanoseconds.  Does not include time the system was
                     suspended.  See: clock_gettime(CLOCK_MONOTONIC)

              Return Current ktime.
*/
    let ts          = unsafe { bpf_ktime_get_ns() };
    let syscall     = args[1] as u64;
    let pid         = ctx.pid();
    let message = ctx.command().map_err(|e| e as u32)?;
    let message    = core::str::from_utf8_unchecked(&message[..]);

    /*
        id    : syscall id
        pid   : process pid of process calling the syscall
        binary: binary ran during the syscall
    */
    info!(&ctx, "ts: {}ns | id: {} | pid: {} | binary: {}",bpf_ktime_get_ns() - ts,syscall,pid,message);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
