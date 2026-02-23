# Calling Convention Design: CCL vs Genera

## CCL x86-64 Calling Convention

### Register Allocation

```
LISP REGISTERS:
  imm0 = RAX        ; Immediate/scratch, also return value
  imm1 = RDX        ; Immediate/scratch
  imm2 = RCX        ; Immediate, ALSO nargs (argument count!)

  arg_z = RSI       ; Argument 0 (rightmost)
  arg_y = RDI       ; Argument 1
  arg_x = R8        ; Argument 2

  temp0 = RBX       ; Also: fname, allocptr
  temp1 = R9        ; Also: xfn (for tail calls)
  temp2 = R10       ; Also: ra0 (return address)
  temp3 = R15       ; Preserved
  temp4 = R14       ; Preserved
  temp5 = R12       ; Preserved
  temp6 = R11       ; Also: rcontext on Windows

  fn    = R13       ; Current function pointer

  rcontext = GS     ; Thread context (segment register)

CONSTANTS:
  nargregs = 3      ; Args in registers: arg_x, arg_y, arg_z
  fixnumshift = 3   ; Fixnums shifted left 3 bits
```

### Function Call Sequence

**Caller side:**
```asm
; Calling (foo x y z) with 3 args
set_nargs(3):
    xorl %ecx, %ecx           ; Clear nargs
    addl $24, %ecx            ; nargs = 3 << 3 = 24 (fixnum 3)

; Arguments in registers (right-to-left):
    ; arg_z (RSI) = z
    ; arg_y (RDI) = y
    ; arg_x (R8)  = x

; If more than 3 args, extras go on stack (pushed right-to-left)

do_funcall():
    movb %bl, %al             ; Get low byte of temp0 (the function)
    andb $15, %al             ; Extract fulltag
    cmpb $14, %al             ; fulltag_symbol?
    cmovgq %rbx, %r13         ; If function, fn = temp0
    jl bad                    ; If < symbol tag, error
    cmoveq symbol.fcell(%rbx), %r13  ; If symbol, fn = symbol's function cell
    jmp *%r13                 ; Jump to function
```

**Callee side (function entry):**
```asm
; Function object layout:
;   +0: header (subtag_function)
;   +8: code-size
;   +16: entry-point offset (usually 0)
;   +24: constants vector
;   ... then native code at entry point
```

### Multiple Values

CCL uses a clever trick: **ret1val_addr** is a special return address that signals "I want multiple values."

**Returning single value:**
```asm
; Result in arg_z (RSI)
ret
```

**Returning multiple values (VALUES form):**
```asm
_spentry(values):
    movq (%temp0), %ra0           ; Get return address
    cmpq ret1val_addr, %ra0       ; Is caller expecting MVs?
    je handle_multiple_values     ; Yes: copy all values

    ; No: caller wants single value
    movl $nil, %arg_z_l           ; Default to NIL
    testl %nargs, %nargs          ; Any values?
    cmovneq -8(%rsp,%rcx), %arg_z ; Yes: get first value
    movq %temp0, %rsp
    ret

handle_multiple_values:
    ; Copy nargs values up the stack
    ; Return to actual caller (skip ret1val_addr frame)
```

**Caller expecting multiple values:**
```asm
; Push special return address
    call function
    .long ret1val_addr    ; <- Special marker
actual_return:
    ; nargs = number of values
    ; Values on stack
```

### Save/Recover Values (for MULTIPLE-VALUE-PROG1)

```asm
_spentry(save_values):
    ; Save current values to temp stack (TSP)
    ; Creates linked list of value frames

_spentry(recover_values):
    ; Walk linked list backwards
    ; Push values back onto value stack
    ; Accumulate nargs
```

## Genera Approach (from Moon's paper)

### Object-Oriented Memory

> "An object is referenced by its address plus six tag bits."

Three representations:
1. **Small objects (cons)**: Just fields, type in address
2. **Large objects**: Header word + data
3. **Immediates**: Entirely in the reference

### Full Tagging

> "The introduction of tag bits on every memory word in 1983 significantly
> simplified the implementation, and as a result significantly improved
> performance."

Key insight: Given any memory word, you can immediately know what it is.
No need to look elsewhere for type information.

### No Protected Kernel

> "Genera... has a truly open structure in which no firm distinction is
> drawn between user programs and system programs."

Single address space, language-based safety. This is what Mezzano does too.

### Exception Handling

Genera pioneered conditions/restarts:
- Condition objects with class hierarchy
- Handlers that can proceed or restart
- Recovery is first-class

This became Common Lisp's condition system.

## Design for Modus 64-bit

Taking the best from both:

### Register Convention (CCL-inspired)

```
LISP REGISTERS:
  RAX = imm0        ; Return value, scratch
  RCX = nargs       ; Argument count (fixnum)
  RDX = imm1        ; Scratch

  RSI = arg0        ; First argument (like CCL's arg_z)
  RDI = arg1        ; Second argument
  R8  = arg2        ; Third argument
  R9  = arg3        ; Fourth argument (one more than CCL!)

  RBX = temp0       ; Callee-saved temp
  R10 = temp1       ; Scratch temp
  R11 = temp2       ; Scratch temp

  R12 = alloc       ; Allocation pointer
  R13 = fn          ; Current function
  R14 = limit       ; Allocation limit (for fast GC check)
  R15 = nil         ; Always points to NIL (constant)

  GS  = tcr         ; Thread context register

  nargregs = 4      ; One more than CCL!
```

### Function Call (simplified)

```asm
; Call with args in RSI, RDI, R8, R9
; nargs in RCX (as fixnum)
; Function in RBX

funcall:
    movb %bl, %al
    andb $0x0F, %al           ; Extract tag
    cmpb $TAG_FUNCTION, %al
    je .call_it
    cmpb $TAG_SYMBOL, %al
    jne .error
    movq SYMBOL_FUNCTION(%rbx), %r13
    jmp *%r13
.call_it:
    movq %rbx, %r13
    jmp *%r13
```

### Multiple Values (simplified)

Use a dedicated MV area in thread context instead of stack manipulation:

```
TCR layout:
  +0:   current-thread
  +8:   mv-count        ; Number of values (0 = use RAX)
  +16:  mv-area[0..63]  ; Up to 64 multiple values
```

**Returning multiple values:**
```asm
; Put count in TCR.mv-count
; Put values in TCR.mv-area (or first in RAX)
; Return normally
```

**MULTIPLE-VALUE-BIND:**
```asm
; After call:
    movq tcr.mv_count(%gs), %rcx
    testq %rcx, %rcx
    jz .single_value        ; mv-count=0 means single value in RAX
    ; Read from tcr.mv_area
```

This avoids CCL's complex stack manipulation while still being efficient.

### Object Layout (Genera-inspired)

Everything is an object. Every word can be identified:

```
Tags (4 bits):
  xxx0 = Fixnum (63 bits of integer)
  0001 = Cons pointer
  1001 = Object pointer
  0101 = Immediate (char, single-float)
  1111 = GC forwarding

Object header (8 bytes):
  [subtag:8][unused:8][element-count:48]
```

### Exception Handling (Genera-inspired)

Conditions are objects. Full proceed/restart support.

```lisp
(define-condition file-error (error)
  ((pathname :initarg :pathname)))

(handler-bind ((file-error
                (lambda (c)
                  (invoke-restart 'use-alternate-file "backup.txt"))))
  (open-file "missing.txt"))
```

## Summary: What We Take

| Aspect | CCL | Genera | Modus |
|--------|-----|--------|-------|
| Tags | 4-bit fulltag | 6-bit tag | 4-bit (Mezzano-style) |
| Args in regs | 3 | ? | 4 |
| MV handling | Stack + ret1val | ? | TCR area |
| Memory model | Objects | Everything is object | Everything is object |
| Protection | None (single space) | None (open system) | None (language safety) |
| Exceptions | CL conditions | Conditions + restarts | Full CL conditions |

## Key Insight

Both CCL and Genera prove that a single-address-space, no-kernel Lisp works well.
The key is:
1. Full tagging (every word self-describing)
2. Object-oriented memory (no raw bits)
3. Well-defined protocols between components

We have all the pieces. Time to build.
