# X25519 Assembly Optimization Notes

## Current Status

TLS 1.3 handshakes work with pure Lisp X25519 implementation. Assembly optimization attempts have not yet succeeded.

## Background

X25519 is the elliptic curve Diffie-Hellman used in TLS 1.3. The field arithmetic is over F_p where p = 2^255 - 19.

### Representation

We use 10 x 26-bit limbs = 260 bits total. This gives room for carries during intermediate computations.

### The Wrap Factor Problem

When multiplying two field elements, products "wrap around" mod p:
- 2^260 mod p = 2^260 mod (2^255 - 19)
- 2^260 = 2^5 * 2^255 = 32 * (p + 19) = 32p + 608
- So 2^260 ≡ 608 (mod p)

**Important**: Factor 608, NOT 38. The donna implementations use factor 38 because they use 51-bit limbs (5 x 51 = 255 bits), where 2^255 ≡ 38 (mod p).

## Assembly Attempts

### Attempt 1: Per-Product Factor 608

Multiply each wrapped product by 608 individually, then add to accumulator.

**Problem**: Overflow in accumulator.
- 9 wrapped products per row (worst case)
- Each product: up to 2^52 (26-bit × 26-bit)
- Each × 608: up to 2^61.25
- Sum of 9: up to 2^64.5 - OVERFLOW!

### Attempt 2: Batched Multiplication

Accumulate wrapped products in batches of 4, multiply each batch by 608, then add to main accumulator.

**Math**:
- 4 products max = 4 × 2^52 = 2^54
- × 608 = 2^63.25 - fits in 64 bits!

**Implementation** (`fe-mul-asm-batched`):
- Stack layout: [main-lo][main-hi][g-ptr][acc-ptr][batch-lo][batch-hi][saved-esi][saved-ebx]
- Direct products add to main accumulator
- Wrapped products add to batch accumulator
- After every 4 wrapped products (or end of row), multiply batch by 608 and add to main

**Status**: Implemented but causes system hang during boot. Bug not yet identified.

## Stack Layout for Batched Version

```
After setup (ESP points to main-lo):
  (:esp 0)  = main-lo      (64-bit accumulator low)
  (:esp 4)  = main-hi      (64-bit accumulator high)
  (:esp 8)  = g-ptr        (pointer to g array)
  (:esp 12) = acc-ptr      (pointer to output acc array)
  (:esp 16) = batch-lo     (batch accumulator low)
  (:esp 20) = batch-hi     (batch accumulator high)
  (:esp 24) = saved ESI
  (:esp 28) = saved EBX
```

## Batch Multiply Sequence

```lisp
;; Multiply batch by 608 and add to main accumulator
(:movl (:esp 16) :eax)        ; batch lo
(:movl (:esp 20) :edx)        ; batch hi
(:pushl :edx)                 ; save batch hi
(:pushl :eax)                 ; save batch lo
(:movl 608 :ecx)
(:mull :ecx :eax :edx)        ; batch_lo * 608 -> EDX:EAX
(:addl :eax (:esp 8))         ; add to main acc lo (offset +8 due to pushes)
(:adcl :edx (:esp 12))        ; add carry to main acc hi
(:movl (:esp 4) :eax)         ; batch hi
(:mull :ecx :eax :edx)        ; batch_hi * 608 -> EDX:EAX
(:addl :eax (:esp 12))        ; add to main acc hi
(:addl 8 :esp)                ; pop saved batch
(:movl 0 (:esp 16))           ; clear batch lo
(:movl 0 (:esp 20))           ; clear batch hi
```

## Files

- `/lib/movitz/losp/lib/crypto/x25519.lisp` - Main implementation
- `/tmp/gen-batched-asm.py` - Python script to generate batched assembly
- `/tmp/batched-asm.lisp` - Generated assembly output

## Next Steps

1. Debug why batched assembly causes hang
2. Add isolated test that doesn't run during boot
3. Compare assembly output byte-by-byte with Lisp version
4. Consider alternative approaches:
   - Smaller limbs (25-bit) to reduce wrap factor
   - Lazy reduction (accumulate without factor, reduce at end)
   - Different batching strategy

## Working Pure Lisp Version

The current working implementation uses pure Lisp with bignums:

```lisp
(defun fe-mul (f g)
  (let ((f0 (aref f 0)) ... (f9 (aref f 9))
        (g0 (aref g 0)) ... (g9 (aref g 9)))
    (let ((g1-608 (* g1 608)) ... (g9-608 (* g9 608)))
      (let ((h0 (+ (* f0 g0) (* f1 g9-608) ...))
            ...)
        (fe-carry (vector h0 h1 ... h9))))))
```

This works correctly but allocates bignums for intermediate results, which is slow and causes GC pressure.
