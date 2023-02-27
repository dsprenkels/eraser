#![deny(missing_docs)]

/*!
This crate provides a runtime context that allows you to securely run code that
deals with secrets, for example cryptographic code.  It does this by allocating
a separate stack and on the heap and executing the user-supplied code with the
separate stack.  After running the code, we erase the complete stack and (on
x86_64) we wipe all the CPU registers before returning.
*/

// TODO: Support for Cortex-M4

use std::{alloc, arch, cell, panic, ptr};

const STACK_ALIGN: usize = 32;
const ERASE_VALUE: usize = 0xDEADBEEF_DEADBEEF;

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
    static CTX: cell::RefCell<EraserContext> = Default::default();
}

unsafe fn erase(ptr_mut: *mut u8, len: usize) {
    assert_eq!(ptr_mut.align_offset(core::mem::size_of::<usize>()), 0);
    for offset in (0..len).step_by(core::mem::size_of::<usize>()) {
        let cur = ptr_mut.add(offset) as *mut usize;
        ptr::write_volatile(cur, ERASE_VALUE);
    }
}

/// Run a function on a ephemeral stack and immediately erase the stack
///
/// This function is similar to [`run_then_erase`] but allows the user to
/// provice their own buffer for the stack.  This is useful when there is no
/// allocator present, or when the internal stack can be small enough such
/// that it can be stored on the caller stack.
///
/// ## Safety
///
/// * The proviced stack buffer must have a length divisible by 32.
/// * The provided stack buffer must be aligned to 32 bytes.
/// * The stack buffer must be large enough for the user function.
///
/// ## Example
/// ```
/// use core::cell::RefCell;
///
/// thread_local! {
///     static RESULT: RefCell<i32> = RefCell::default();
/// }
///
/// #[repr(C, align(32))]
/// struct AlignedStack { buf: [u8; 4096] };
///
/// let mut stack = AlignedStack { buf: [0; 4096] };
/// unsafe {
///     eraser::run_then_erase_with_stack(|| {
///         RESULT.with(|x| x.replace(42));
///     }, &mut stack.buf);
/// }
///
/// RESULT.with(|x| assert_eq!(*x.borrow(), 42));
/// ```
pub unsafe fn run_then_erase_with_stack(f: fn(), stack: &mut [u8]) {
    let stack_ptr = stack.as_mut_ptr();
    let stack_top = stack_ptr.add(stack.len());

    // Check if the stack meets all our criteria
    assert_eq!(
        stack_ptr as usize % STACK_ALIGN,
        0,
        "stack buffer @ {:p} is not aligned to {}",
        stack_ptr,
        STACK_ALIGN
    );
    assert_eq!(
        stack_top as usize % STACK_ALIGN,
        0,
        "stack top @ {:p} is not aligned to {} (is the buffer length divisible by {}?)",
        stack_ptr,
        STACK_ALIGN,
        STACK_ALIGN
    );

    // Initialize EraserContext
    CTX.with(|cell| {
        cell.replace(EraserContext {
            user_fn: Some(f),
            panic_result: None,
        })
    });

    // Switch the location of the stack and call the wrapper function
    unsafe {
        stack_switch(stack_top);
        erase(stack_ptr, stack.len());
    };

    CTX.with(|cell| {
        // Double-check that the user function did indeed finish
        assert!(cell.borrow().panic_result.is_some());

        // If the user function panicked, resume that panic now
        let ctx = cell.take();
        if let Some(Err(err)) = ctx.panic_result {
            panic::resume_unwind(err);
        }
    });

    // Erase the stack and wipe all the registers
    unsafe {
        erase(stack_ptr, stack.len());
        wipe_all_registers();
    }
}

/// Run a function on an ephemeral stack and immediately erase the stack.
///
/// The `stack_size` specifies the size of the stack that will be provided to
/// the user function.  It must be a multiple of 32 bytes, or otherwise this
/// function will panic.
pub fn run_then_erase(f: fn(), stack_size: usize) {
    let layout =
        alloc::Layout::from_size_align(stack_size, STACK_ALIGN).expect("incorrect alignment");
    let ptr_opt = ptr::NonNull::new(unsafe { alloc::alloc_zeroed(layout) });
    let mut ptr = ptr_opt.expect("alloc::alloc_zeroed returned null pointer");

    if cfg!(feature = "guard_page") {
        // TODO: Set up a guard page to catch overflows
        unimplemented!("guard pages not implemented")
    }

    unsafe {
        let stack = core::slice::from_raw_parts_mut(ptr.as_mut(), layout.size());
        run_then_erase_with_stack(f, stack);
    }
}

/// Run the "assembly" part of the `run_then_erase` wrapper.
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
unsafe fn stack_switch(stack_top: *mut u8) {
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
        ctx.panic_result = Some(panic::catch_unwind(|| {
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
        lateout("xmm0") _,
        lateout("xmm1") _,
        lateout("xmm2") _,
        lateout("xmm3") _,
        lateout("xmm4") _,
        lateout("xmm5") _,
        lateout("xmm6") _,
        lateout("xmm7") _,
        lateout("xmm8") _,
        lateout("xmm9") _,
        lateout("xmm10") _,
        lateout("xmm11") _,
        lateout("xmm12") _,
        lateout("xmm13") _,
        lateout("xmm14") _,
        lateout("xmm15") _,
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

    #[test]
    fn stack_on_stack() {
        #[repr(C, align(32))]
        struct AlignedStack {
            buf: [u8; 4096],
        }

        let mut stack = AlignedStack { buf: [0; 4096] };
        unsafe {
            run_then_erase_with_stack(
                || {
                    println!("Hello Eraser!");
                },
                &mut stack.buf,
            );
        }
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
