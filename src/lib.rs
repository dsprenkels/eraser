#![deny(missing_docs)]

/*!
This crate provides a runtime context that allows you to securely run code that
deals with secrets, for example cryptographic code.  It does this by allocating
a separate stack and on the heap and executing the user-supplied code with the
separate stack.  After running the code, we erase the complete stack.
*/

use core::arch;
use std::cell::RefCell;
use std::mem;
use std::panic::resume_unwind;
use std::ptr::null_mut;
use std::{alloc, mem::size_of, panic::catch_unwind, ptr};

#[derive(Debug, Default)]
struct EraserContext {
    user_fn: Option<fn()>,
    thread_result: Option<std::thread::Result<()>>,
}

thread_local! {
    static CTX: RefCell<EraserContext> = Default::default();
}

struct Memory {
    layout: alloc::Layout,
    ptr: *mut u8,
}

impl Drop for Memory {
    fn drop(&mut self) {
        self.erase();
        unsafe {
            alloc::dealloc(self.ptr, self.layout);
        }
        self.ptr = null_mut();
    }
}

impl Memory {
    fn new(layout: alloc::Layout) -> Self {
        assert_ne!(layout.size(), 0);
        Self {
            layout,
            // SAFETY:
            //   * Checked that the size is not equal to 0.
            ptr: unsafe { alloc::alloc_zeroed(layout) },
        }
    }

    fn erase(&mut self) {
        let mut offset = 0;
        while offset < self.layout.size() {
            unsafe {
                let cur = self.ptr.offset(offset as isize) as *mut u64;
                ptr::write_volatile(cur, 0xDEADBEEF);
            }
            offset += size_of::<u64>()
        }
    }
}

/// Run a function on a ephemeral stack and immediately erase the stack
pub fn run_then_erase(f: fn(), stack_size: usize) {
    // TODO: Document/enforce valid stack_size values

    let stack_align = 1024 * 1024;
    let layout =
        alloc::Layout::from_size_align(stack_size, stack_align).expect("Layout::from_size_align");
    let mut mem = Memory::new(layout);

    if cfg!(feature = "guard_page") {
        // TODO: Set up a guard pagse to prevent overflows
        unimplemented!("guard pages not implemented")
    }

    // Initialize EraserContext
    CTX.with(|cell| {
        cell.replace(EraserContext {
            user_fn: Some(f),
            thread_result: None,
        })
    });

    // Call user function through wrapper
    unsafe {
        let stack_top = mem.ptr.offset(stack_size as isize);
        arch::asm!(
            // Stash the old rsp
            "mov rax, rsp",
            // Switch stacks
            "mov rsp, {stack_top}",
            // Save the original stack and frame pointer values
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
            user_fn = in(reg) do_run_user_fn,
            stack_top = in(reg) stack_top,
            out("rax") _,
        );
    };

    // Double-check that the user function did indeed finish
    CTX.with(|cell| assert!(cell.borrow().thread_result.is_some()));

    // If the user function panicked, resume that panic now
    CTX.with(|cell| {
        let ctx = cell.take();
        if let Some(Err(err)) = ctx.thread_result {
            // For an unknown reason, memory curruption occurs when we
            // resume unwinding.  Presumable, the backtrace tool tries to read
            // from the stack thats has already been deallocated.
            // This should be fixed when we provide a complete context to the
            // library user.
            mem.erase();
            mem::forget(mem);

            resume_unwind(err);
        }
    });
}

extern "C" fn do_run_user_fn() {
    CTX.with(|cell| {
        let mut ctx = cell.borrow_mut();
        let user_fn_opt = ctx.user_fn;
        let thread_result = catch_unwind(|| user_fn_opt.expect("EraserContext.user_fn is None"));
        let user_fn = match thread_result {
            Ok(x) => x,
            Err(err) => {
                ctx.thread_result = Some(Err(err));
                return;
            }
        };
        ctx.thread_result = Some(catch_unwind(|| user_fn()));
    });
}

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
    fn panicking() {
        run_then_erase(do_panic, 4096);
    }
}
