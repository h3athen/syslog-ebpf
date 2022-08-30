
use std::io;

use csv;
use serde::Serialize;
use aya::{include_bytes_aligned, Bpf};
use aya::{
    programs::TracePoint,util::online_cpus,maps::perf::AsyncPerfEventArray,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use syslog_common::SysCallLog;
use tokio::{
    signal, task,
};
use tokio::sync::mpsc;

#[derive(Debug, Parser)]
struct Opt {
    
}

#[derive(Debug, Serialize)]
struct CsvLog {
    ts: u64,
    id: u32,
    pid:u32,
    pname: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syslog"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/syslog"
    ))?;
    BpfLogger::init(&mut bpf)?;
    let program: &mut TracePoint = bpf.program_mut("syslog").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;

    /* ------------------------------------ */
    // mapping to the EVENTS
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    // defining writer path to file
    let mut writer = csv::Writer::from_path("output.csv")?;

    let (tx, mut rx) = mpsc::channel::<SysCallLog>(1024);
    let _tx_writer = tx.clone();
    task::spawn(async move {
        while let Some(data) = rx.recv().await {
            let pname = unsafe { String::from_utf8_unchecked(data.pname_bytes[..].to_vec()) };
            writer.serialize(CsvLog {
                                    ts: data.ts,
                                    id: data.syscall,
                                    pid: data.pid,
                                    pname,
                                }).unwrap();
            writer.flush().unwrap();
        }
    });

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in &buffers[..events.read] {
                    let data = unsafe { (buf.as_ptr() as *const SysCallLog).read_unaligned() };
                    tx.send(data).await;
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
