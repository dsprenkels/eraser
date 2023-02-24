#![deny(missing_docs)]

/*!
This crate provides a runtime context that allows you to securely run code that
deals with secrets, for example cryptographic code.  It does this by allocating
a separate stack and on the heap and executing the user-supplied code with the
separate stack.  After running the code, we erase the complete stack.
*/

// TODO: Support for Cortex-M4
// TODO: Also clear all data registers when erasing

use core::arch;
use std::cell::RefCell;
use std::panic::resume_unwind;
use std::{alloc, mem::size_of, panic::catch_unwind, ptr};

const ERASE_VALUE: u64 = 0xDEADBEEF_DEADBEEF;

/// EraserContext contains any information that needs to be passed across the
/// stack switch barrier from `run_then_erase_asm`.
#[derive(Debug, Default)]
struct EraserContext {
    /// Function specified by the user that should be run in the separate stack.
    user_fn: Option<fn()>,
    /// Panic result describes whether the user's function panicked.  If a
    /// panic occurred, `panic_result` will encapsulate the error;  if the
    /// user function succeeded without panic, `panic_result` will be equal
    /// to `Some(Ok(()))`.
    panic_result: Option<std::thread::Result<()>>,
}

thread_local! {
    static CTX: RefCell<EraserContext> = Default::default();
}

#[derive(Debug, Clone)]
struct Memory {
    layout: alloc::Layout,
    ptr: std::ptr::NonNull<u8>,
}

impl Drop for Memory {
    fn drop(&mut self) {
        self.erase();
        unsafe {
            let ptr_mut = self.ptr.as_mut();
            alloc::dealloc(ptr_mut, self.layout);
        }
    }
}

impl Memory {
    fn new(layout: alloc::Layout) -> Self {
        assert_ne!(layout.size(), 0);
        // SAFETY:
        //   * Checked that the size is not equal to 0.
        let ptr_opt = core::ptr::NonNull::new(unsafe { alloc::alloc_zeroed(layout) });
        let ptr = ptr_opt.expect("alloc::alloc_zeroed returned null pointer");
        Self { layout, ptr }
    }

    fn erase(&mut self) {
        let mut offset = 0;
        let ptr_mut: *mut u8 = unsafe { self.ptr.as_mut() };
        assert_eq!(ptr_mut.align_offset(core::mem::size_of::<u64>()), 0);
        while offset < self.layout.size() {
            unsafe {
                let cur = ptr_mut.add(offset) as *mut u64;
                ptr::write_volatile(cur, ERASE_VALUE);
            }
            offset += size_of::<u64>()
        }
    }
}

/// Run a function on a ephemeral stack and immediately erase the stack
///
/// The `stack_size` specifies the size of the stack that will be provided to
/// the user function.  It must be a multiple of 32 bytes, or otherwise this
/// function will panic.
pub fn run_then_erase(f: fn(), stack_size: usize) {
    let stack_align = 32;
    if stack_size % 32 != 0 {
        panic!(
            "stack size ({}) not a multiple of {}",
            stack_size, stack_align
        );
    }
    let layout =
        alloc::Layout::from_size_align(stack_size, stack_align).expect("Layout::from_size_align");
    let mut mem = Memory::new(layout);

    if cfg!(feature = "guard_page") {
        // TODO: Set up a guard page to prevent overflows
        unimplemented!("guard pages not implemented")
    }

    // Initialize EraserContext
    CTX.with(|cell| {
        cell.replace(EraserContext {
            user_fn: Some(f),
            panic_result: None,
        })
    });

    // Switch the location of the stack and call the wrapper function
    unsafe {
        let raw_ptr: *mut u8 = mem.ptr.as_mut();
        let stack_top = raw_ptr.add(mem.layout.size());
        run_then_erase_asm(stack_top);
    };

    // Double-check that the user function did indeed finish
    CTX.with(|cell| assert!(cell.borrow().panic_result.is_some()));

    // If the user function panicked, resume that panic now
    CTX.with(|cell| {
        let ctx = cell.take();
        if let Some(Err(err)) = ctx.panic_result {
            drop(mem); // Make sure the panic handler cannot access secret data
            resume_unwind(err);
        }
    });
    unsafe {
        wipe_all_registers();
    }
}

/// Run the "assembly" part of the `run_then_erase` function.
///
/// This function is separate, because the user function might clobber any kind
/// of register, even avx2 or x87 registers.  Instead of clobbering *all* of
/// them in the asm! directive, we enter a separate function that explicitly
/// uses the C ABI.  This way, we know with reasonably certainty that the
/// calling function has saved any reasonable register that it needs to stay
/// intact.
///
/// The API allows the user function to capture from its environment, but this
/// prevents it from being compatible with the C ABI.  Therefore, we cannot
/// store and pass it directly through calls that use the C calling convention.
/// So, instead of directly passing them through the layer, we bypass the layer
/// and stash the user function thread local storage static value `CTX`.
/// `do_run_user_fn` will read back the user function out from `CTX` and
/// execute it using the (unstable) Rust ABI convention (but on the other
/// stack).
#[inline(never)]
unsafe fn run_then_erase_asm(stack_top: *mut u8) {
    // TODO: Go through and guarantee the inline assembly rules listed at
    // https://doc.rust-lang.org/reference/inline-assembly.html

    arch::asm!(
        // Stash the old rsp
        "mov rax, rsp",
        // Switch stacks
        "mov rsp, {stack_top}",
        // Save the frame pointer and stack pointer values
        "push rbp",
        "push rax",
        // Put the return address on the top of the stack
        "lea rax, [9999f + rip]",
        "push rax",
        // Call the running function using the new stack
        "jmp {user_fn}",
        // Wrapped function will return to here
        "9999:",
        // Restore the original stack and frame pointer values
        "pop rax",
        "pop rbp",
        "mov rsp, rax",
        user_fn = sym do_run_user_fn,
        stack_top = in(reg) stack_top,
        out("rax") _,
    );
}

extern "C" fn do_run_user_fn() {
    CTX.with(|cell| {
        let mut ctx = cell.borrow_mut();
        let user_fn_opt = ctx.user_fn;
        ctx.panic_result = Some(catch_unwind(|| {
            let user_fn = user_fn_opt.expect("EraserContext.user_fn is None");
            user_fn()
        }));
    });
}

#[cfg(target_arch = "x86_64")]
unsafe fn wipe_all_registers() {
    arch::asm!(
        "xor rax, rax",
        "xor rcx, rcx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rdi, rdi",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "vzeroall",
        lateout("rax") _,
        lateout("rcx") _,
        lateout("rdx") _,
        lateout("rsi") _,
        lateout("rdi") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        lateout("r11") _,
        lateout("r12") _,
        lateout("r13") _,
        lateout("r14") _,
        lateout("r15") _,
    )
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn wipe_all_registers() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug, Clone, Copy, Default)]
    struct CryptoSimulInfo {
        ctr: i32,
    }

    thread_local! {
        static INFO: RefCell<CryptoSimulInfo> = Default::default();
    }

    fn bump_ctr() {
        INFO.with(|cell| {
            (*cell.borrow_mut()).ctr += 1;
        });
    }

    #[test]
    fn functional() {
        INFO.with(|cell| {
            (*cell.borrow_mut()).ctr = 0;
        });
        run_then_erase(bump_ctr, 4096);
        let mut ctr = 0;
        INFO.with(|cell| {
            ctr = (*cell.borrow()).ctr;
        });
        assert_eq!(ctr, 1);
    }

    fn do_panic() {
        panic!();
    }

    #[test]
    #[should_panic]
    fn explicit_panic() {
        run_then_erase(do_panic, 4096);
    }
}
