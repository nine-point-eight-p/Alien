use heapless::Vec;
use serde::Deserialize;
use syscall2struct_derive::MakeSyscall;
use syscall2struct_helpers::*;
use syscalls::raw::*;
use uuid::Uuid;

// This is a test syscall
#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(0)]
pub struct Foo {
    pub a: u64,
    pub b: u64,
    #[in_ptr]
    pub buf: Pointer<Vec<u8, 4096>>,
    pub res: SyscallResult,
}

// This is also a test syscall
#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(1)]
pub struct Bar {
    #[ret_val]
    pub id: Uuid,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(56)]
pub struct Openat {
    pub fd: SyscallResult,
    #[in_ptr]
    pub file: Pointer<Vec<u8, 4096>>,
    pub flags: u64,
    pub mode: u64,
    #[ret_val]
    pub id: Uuid,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(57)]
pub struct Close {
    pub fd: SyscallResult,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(49)]
pub struct Chdir {
    #[in_ptr]
    pub filename: Pointer<Vec<u8, 4096>>,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(37)]
pub struct Linkat {
    pub oldfd: SyscallResult,
    #[in_ptr]
    pub old: Pointer<Vec<u8, 4096>>,
    pub newfd: SyscallResult,
    #[in_ptr]
    pub new: Pointer<Vec<u8, 4096>>,
    pub flags: u64,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(35)]
pub struct Unlinkat {
    pub fd: SyscallResult,
    #[in_ptr]
    pub path: Pointer<Vec<u8, 4096>>,
    pub flags: u64,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(34)]
pub struct Mkdirat {
    pub fd: SyscallResult,
    #[in_ptr]
    pub path: Pointer<Vec<u8, 4096>>,
    pub mode: u64,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(23)]
pub struct Dup {
    pub oldfd: SyscallResult,
    #[ret_val]
    pub id: Uuid,
}

#[derive(Debug, Deserialize, MakeSyscall)]
#[sysno(24)]
pub struct Dup3 {
    pub oldfd: SyscallResult,
    pub newfd: SyscallResult,
    pub flags: u64,
    #[ret_val]
    pub id: Uuid,
}
