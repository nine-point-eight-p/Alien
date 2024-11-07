#![no_std]
#![no_main]

use libafl_qemu_cmd::{self, EndStatus};
use postcard::take_from_bytes;
use syscall2struct_helpers::{MakeSyscall, Pointer, ResultContainer, SyscallResult};
use Mstd::{print, println};

mod syscall;
use syscall::*;

#[no_mangle]
fn main() {
    println!("Hello, fuzzing!");

    const BUFFER_SIZE: usize = 0x1000 * (10 + 1);
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut results = ResultContainer::new();

    let size = libafl_qemu_cmd::start_virt(buffer.as_mut_ptr(), BUFFER_SIZE);
    // println!("Bytes: {}", size);

    let (len, mut current) = take_from_bytes::<u32>(&buffer[..size]).unwrap();
    // println!("Number of calls: {}", len);

    for i in 0..len {
        let Ok((nr, next)) = take_from_bytes::<u32>(current) else {
            break;
        };
        current = next;

        let Ok(next) = test_one(nr as i32, current, &mut results) else {
            break;
        };
        current = next;
    }

    println!("----------");
    libafl_qemu_cmd::end(EndStatus::Ok);
}

fn test_one_foobar<'input>(
    nr: i32,
    current: &'input [u8],
    results: &mut ResultContainer,
) -> Result<&'input [u8], ()> {
    match nr as i32 {
        Foo::NR => match take_from_bytes::<Foo>(current) {
            Ok((bundle, next)) => {
                print!("Foo: a: {}, b: {}, ", bundle.a, bundle.b);
                match bundle.buf {
                    Pointer::Addr(addr) => print!("addr: {}, ", addr),
                    Pointer::Data(data) => print!(
                        "length: {}, data: {:02x?}, ",
                        data.len(),
                        &data[..data.len().min(10)]
                    ),
                }
                println!("res: {:?}", bundle.res);
                if let SyscallResult::Ref(id) = bundle.res {
                    if !results.contains_key(&id) {
                        println!("Error: result not found: {}", id);
                        return Err(());
                    }
                }
                Ok(next)
            }
            Err(e) => {
                println!("Failed to parse foo, error: {:?}", e);
                Err(())
            }
        },
        Bar::NR => match take_from_bytes::<Bar>(current) {
            Ok((bundle, next)) => {
                println!("Bar: id: {}", bundle.id);
                results.insert(bundle.id, 0);
                Ok(next)
            }
            Err(e) => {
                println!("Failed to parse bar, error: {:?}", e);
                Err(())
            }
        },
        _ => {
            println!("Unknown syscall number: {}", nr);
            Err(())
        }
    }
}

fn test_one<'input>(
    nr: i32,
    current: &'input [u8],
    results: &mut ResultContainer,
) -> Result<&'input [u8], ()> {
    match nr as i32 {
        Dup::NR => match take_from_bytes::<Dup>(current) {
            Ok((bundle, next)) => {
                // println!("Dup: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    Err(())
                } else {
                    println!("dup success: {}", result);
                    results.insert(bundle.id, result as usize);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse dup, error: {}", e);
                Err(())
            }
        },
        Dup3::NR => match take_from_bytes::<Dup3>(current) {
            Ok((bundle, next)) => {
                // println!("Dup3: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    Err(())
                } else {
                    println!("dup3 success: {}", result);
                    results.insert(bundle.id, result as usize);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse dup3, error: {}", e);
                Err(())
            }
        },
        Chdir::NR => match take_from_bytes::<Chdir>(current) {
            Ok((bundle, next)) => {
                // println!("Chdir: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    Err(())
                } else {
                    println!("chdir success: {}", result);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse chdir, error: {}", e);
                Err(())
            }
        },
        Openat::NR => match take_from_bytes::<Openat>(current) {
            Ok((bundle, next)) => {
                // println!("Openat: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    println!("openat failed, flag: {:08x}", bundle.flags);
                    Err(())
                } else {
                    println!("openat success: {}", result);
                    results.insert(bundle.id, result as usize);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse openat, error: {}", e);
                Err(())
            }
        },
        Close::NR => match take_from_bytes::<Close>(current) {
            Ok((bundle, next)) => {
                // println!("Close: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    Err(())
                } else {
                    println!("close success: {}", result);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse close, error: {}", e);
                Err(())
            }
        },
        Linkat::NR => match take_from_bytes::<Linkat>(current) {
            Ok((bundle, next)) => {
                // println!("Linkat: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    Err(())
                } else {
                    println!("linkat success: {}", result);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse linkat, error: {}", e);
                Err(())
            }
        },
        Unlinkat::NR => match take_from_bytes::<Unlinkat>(current) {
            Ok((bundle, next)) => {
                // println!("Unlinkat: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    Err(())
                } else {
                    println!("unlinkat success: {}", result);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse unlinkat, error: {}", e);
                Err(())
            }
        },
        Mkdirat::NR => match take_from_bytes::<Mkdirat>(current) {
            Ok((bundle, next)) => {
                // println!("Mkdirat: {:?}", bundle);
                let result = bundle.call(results);
                if result < 0 {
                    Err(())
                } else {
                    println!("mkdirat success: {}", result);
                    Ok(next)
                }
            }
            Err(e) => {
                println!("Failed to parse mkdirat, error: {}", e);
                Err(())
            }
        },
        _ => {
            println!("Unknown syscall number: {}", nr);
            Err(())
        }
    }
}
