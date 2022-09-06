# syslog

## Prerequisites

This project uses Aya library. To set it up, follow these intructions <br>
https://aya-rs.dev/book/start/development/#starting-a-new-project 

## Build eBPF

Check the `Makefile`. `make` command will build and run the binary. 

## What is Syslog
syslog logs all the syscalls called by the running processes in a system and writes into a `CSV file`.<br>

Output Format:
```
    ts    : time stamp
    id    : syscall id
    pid   : pid of process calling the syscall
    pname : process name
    path  : path to actual binary
```