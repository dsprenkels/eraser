# Eraser

`eraser` is a small research crate in which I try to explore if it is possible
to robustly clean up the memory of a function after it has run.

## Usage

```rust
use core::cell::RefCell;

thread_local! {
    static CRYPTO_DATA: RefCell<Vec<u8>> = RefCell::default();
}

fn do_crypto(crypto_data: &mut Vec<u8>) {
    // Do some complicated cryptographic operation
}

unsafe {
    eraser::run_then_erase(|| {
        RESULT.with(|cell| do_crypto(cell.borrow_mut()));
    }, 128 * 1024);
}
```

## Why

Cryptographic code deals constantly with values that should remain secret.
These secrets live on the stack, on the heap, and in registers.
Unfortunately, these secrets are often not erased after the code has finished
running.  Even though implementors do their best to try and erase _as much as
possible_, nothing is guaranteed.

The problem is that from inside a high-level language (anything besides
assembly) you _do not have control_ over where your variables are stored.
The compiler can decide, at any time, to spill extra values to the stack, and
which these values will not be erased, no matter how hard you try.
Moreover, best-effort attempts to clear the buffers stored on the stack still
fail to erase values stored in CPU registers.  This is expecially worrysome,
because crypto code often uses the SSE registers, while application code may
not use those, and the secret values will remain in the CPU registers until
_long after_ the crypto code has finished running.

This crate fixes all of these problems and introduces one or two _new_
problems in the process. :)

## How

I thought for a while, and I thing _ideal_ solution is to spawn a new process
for every cryptographic operation.  After every cryptographic operation, the
process gives back the result and exits.  This way the operating system will
clean up the cryptographic secrets, and nobody can access them again later.

Unfortunately, spawning processes (and threads) is expensive.  However, when
we start thinking about it, we only the crypto code to use a different memory
space for its data.

To achieve **real** zeroization after running any cryptographic code, `eraser`
performs the following steps:

  1. Allocate a new stack on the heap,
  2. switch the running stack to the newly allocated "secret" stack,
  3. run the cryptographic code,
  4. switch back to the original stack,
  5. erase the secret stack (i.e., fill it with dummy values),
  6. wipe all the registers, and
  7. return control flow to the caller.

I agree that this method is could be considered "a dirty hack", but it might be
less dirty than you think!  For example, there are other libraries out there
that already contain stack-switching functionality (one common example is
`pthread`).

## Drawbacks

Stack-switching is an operation that is usually not well supported by
programming languages.  In Rust, there is no convenient `switch_stack()`
function, so we have to write that ourselves.
The [stack-switching code] works well, but it is a fragile piece of assembly.
We are messing with the application runtime, and there are so many variables
involved that it is hard to guarantee that everyting is still memory-safe.

Moreover, because Rust does not have a stable ABI, we cannot transfer any kind
of structs or functions through the stack-switching without resorting to using
`#[repr(C)]` or `extern "C" fn` patterns.  This means we have to stash these
mutable values somewhere in `static`, and nobody likes using mutable static
values.

[stack-switching code]: https://github.com/dsprenkels/eraser/blob/cab8a335e8e29c4852ee71a9990d0ae02d701198/src/lib.rs#L173-L195

## Roadmap

* [`thumbv7`] Add support for Cortex-M targets
* [`x86_64` and `linux`] Use guard pages te detect stack overflows.
* Survey other memory-erasing techniques and determine their effectiveness and
  performance
* Write a blog post and/or a small ePrint PDF

## Questions and collaborations

If you are interested in collaborating or if you just have a question, feel
free send me an email on my Github associated e-mail address. :)

## Acknowledgements

This work has been supported by the European Commission through the 
[Starting Grant 805031] (EPOQUE).

[Starting Grant 805031]: https://doi.org/10.3030/805031