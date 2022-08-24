#![no_std]
#![no_main]

use core::slice;

use aya_bpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map,tracepoint},
    maps::{PerfEventArray},
    programs::TracePointContext, BpfContext,
};
use aya_log_ebpf::info;
use syslog_common::SysCallLog;

// Create EVENTS of PerfEventArray type to map struct SysCallLog
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SysCallLog> =
    PerfEventArray::<SysCallLog>::with_max_entries(1024, 0);


/*---------------------------------------------------------------------------*/    
// tracepoint is attached to raw_syscalls/sys_enter
// log: timestamp, syscall id, pid, process name and map to EVENTS
// send EVENTS to userspace
#[tracepoint(name="syslog")]
pub fn syslog(ctx: TracePointContext) -> u32 {
    match unsafe { try_syslog(ctx) } {
        Ok(ret)  => ret,
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
    let oldts          = bpf_ktime_get_ns();
    let syscall        = args[1] as u32;
    let pid            = ctx.pid();
    let pname_bytes= ctx.command().map_err(|e| e as u32)?;
    // let pname         = core::str::from_utf8_unchecked(&pname_bytes[..]);

    /*
        ts    : time stamp
        id    : syscall id
        pid   : pid of process calling the syscall
        pname : process name
    */
    let ts = bpf_ktime_get_ns() - oldts;
    let logs = SysCallLog {
        ts,
        syscall,
        pid,
        pname_bytes,
    };
    // info!(&ctx, "ts: {}ns | id: {} | pid: {} | pname: {}",bpf_ktime_get_ns() - ts,syscall,pid,pname);
    EVENTS.output(&ctx, &logs, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}