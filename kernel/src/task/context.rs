use core::arch::global_asm;

/// 线程切换需要保存的上下文
///
/// 线程切换由__switch()完成，这个汇编函数不会由编译器完成寄存器保存，因此需要手动保存
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Context {
    ra: usize,
    sp: usize,
    s: [usize; 12],
}

impl Context {
    pub fn new(ra: usize, sp: usize) -> Self {
        Self { ra, sp, s: [0; 12] }
    }
    pub const fn empty() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
        }
    }
}

global_asm!(include_str!("switch.asm"));

extern "C" {
    pub fn __switch(current_task_cx_ptr: *mut Context, next_task_cx_ptr: *const Context);
}

pub fn switch(current_task_cx_ptr: *mut Context, next_task_cx_ptr: *const Context) {
    unsafe {
        __switch(current_task_cx_ptr, next_task_cx_ptr);
    }
}
