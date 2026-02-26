# Modus64 Actor Model: Design Document

## Why Actors

ASI workloads are massively parallel: thousands of concurrent reasoning
processes exploring solution spaces, communicating partial results, spawning
sub-tasks dynamically. The traditional threading model (shared memory + locks)
scales poorly to this regime. Locks cause contention, deadlocks, and priority
inversion. Shared mutable state makes reasoning about correctness intractable.

The actor model eliminates these problems by construction:
- **No shared mutable state** -- each actor owns its heap
- **Communication by message** -- async, ordered, typed
- **Fault isolation** -- one actor crashes, others continue
- **Location transparency** -- local actor, remote actor, same protocol
- **Natural parallelism** -- actors on different cores need no synchronization

### Prior Art

| System | Model | Scheduling | Notes |
|--------|-------|-----------|-------|
| **Genera** | Stack groups + cooperative | Timer-assisted preemption | Single CPU, `WITHOUT-INTERRUPTS` for critical sections |
| **Mezzano** | Preemptive threads + mutexes | Priority queues, SMP | Full POSIX-style threading, spinlocks internally |
| **Erlang/BEAM** | Actors (processes) | Preemptive, per-process reduction counting | Per-process heap, copying GC per process, millions of processes |
| **Pony** | Actors + reference capabilities | Work-stealing | Type system prevents data races at compile time |

We take the Erlang path, adapted for a Lisp machine.

---

## Core Concepts

### Actor

An actor is a lightweight process with:
- Its own **cons semispace** (small, growable)
- Its own **object semispace** (small, growable)
- A **mailbox** (message queue)
- A **behavior function** (what to do with each message)
- A **status**: running, waiting, dead
- Minimal saved state: RSP, RIP, registers

Actors are cheap. Creating one costs ~256 bytes of bookkeeping plus two
small heap pages. The goal is millions of live actors.

### Message

A message is an immutable S-expression sent from one actor to another.
Sending a message **copies** it from the sender's heap into the receiver's
heap (or into a shared immutable region). Messages are enqueued in the
receiver's mailbox and processed in order.

For large immutable data (strings, byte arrays, bignums), we can use
**zero-copy sharing** via a read-only shared region. The sender marks
the data immutable; the receiver gets a pointer directly. No copy needed.

### Mailbox

A lock-free FIFO queue. On a single core, this is trivial (no contention).
On SMP, use a Michael-Scott lock-free queue with CAS.

### Supervisor

A supervisor is an actor whose job is to monitor other actors and restart
them on failure. Supervisors form a tree (like Erlang's supervision trees).
Restart strategies: one-for-one, one-for-all, rest-for-one.

---

## Memory Architecture

### Memory Layout

```
0x00000000 - 0x00FFFFFF  Kernel code + statics
0x01000000 - 0x03FFFFFF  Kernel data, symbol table, native code
0x04000000 - 0x04FFFFFF  Boot heap (used during init, before actors)
0x05000000 - 0x0505FFFF  DMA buffers (static, shared)
0x05060000 - 0x050FFFFF  Network state, SSH state
0x05100000 - 0x051FFFFF  Actor table + scheduler state
0x05200000 - 0x052FFFFF  Actor stacks (64KB per actor)
0x05300000 - 0x0531FFFF  Mailbox shared pool (128KB)
0x06000000 - 0x09FFFFFF  Per-actor heaps (1MB per actor, max 64)
```

### Per-Actor Heap Layout

Each actor gets 1MB of heap at `0x06000000 + (id-1) * 0x100000`:

```
Actor N (1-based ID):
  heap_base = 0x06000000 + (N-1) * 0x100000

  +0x000000  Cons semispace A  (256KB)
  +0x040000  Cons semispace B  (256KB)
  +0x080000  Object space      (256KB, bump-allocate, no GC)
  +0x0C0000  Padding           (256KB unused)
```

256KB per cons semispace is enough for most actor computations. The XOR
trick toggles between semispaces: `to_start = from_start XOR 0x40000`.

At 1MB per actor, the range 0x06000000-0x09FFFFFF supports 64 actors
in 512MB QEMU RAM. With larger RAM or virtual memory (future), this
scales further.

### Per-Actor GC (Implemented)

Each actor has its own Cheney copying collector that runs independently:
- **No stop-the-world** -- GC one actor while others run
- **Small heaps = fast GC** -- 256KB takes microseconds to collect
- **No inter-actor pointers** -- mailbox cells live in a shared pool,
  so no cross-actor cons references exist
- **Short-lived actors** -- when an actor dies, its entire 1MB heap is
  freed instantly (no GC needed)

GC triggers inline at every cons allocation site: when R12 >= R14 (cons
semispace full), the GC runs immediately. The collector:
1. Computes semispace bounds from R14 (from_limit = R14, from_start =
   R14 - 0x40000, to_start = from_start XOR 0x40000)
2. Scans the full actor stack (RSP to stack top) for roots
3. Runs the Cheney scan loop to copy live cons cells to to-space
4. Flips semispaces: R12 = new alloc ptr, R14 = new limit

### Mailbox Shared Pool

Mailbox cons cells live in a dedicated shared pool at 0x05300000 (128KB),
not in any actor's heap. This prevents GC from moving cells that are
referenced by another actor's mailbox pointers.

The pool uses a bump allocator with a free list:
- `pool-alloc`: try free list first, then bump allocate
- `pool-free`: push cell onto free list (called by `mailbox-dequeue`)
- Capacity: 8192 cells (128KB / 16 bytes per cell)

---

## Scheduling

### Phase 1: Single-Core Cooperative

A run queue of ready actors. The scheduler picks the next one and runs it
until it either:
1. Calls `(receive)` with an empty mailbox -- blocks, switch to next actor
2. Calls `(yield)` -- voluntary context switch
3. Exhausts its **reduction budget** -- preemption via counter, not timer

Reduction counting (Erlang-style): each function call decrements a counter.
When it hits zero, the actor yields. This gives deterministic, fair scheduling
without needing timer interrupts. The counter resets on each scheduling quantum.

```lisp
;; Scheduler loop (conceptual)
(loop
  (let ((actor (dequeue run-queue)))
    (set-reduction-counter 1000)
    (switch-to-actor actor)
    ;; returns here when actor yields/blocks/exhausts budget
    (cond
      ((actor-dead-p actor) (notify-supervisor actor))
      ((actor-blocked-p actor) (enqueue wait-queue actor))
      (t (enqueue run-queue actor)))))
```

### Phase 2: Timer-Assisted Preemption

Add a PIT/APIC timer interrupt that checks if the current actor has
overrun its budget (for actors that loop without function calls). The timer
handler sets a flag; the next safe point (function entry/loop back-edge)
checks the flag and yields.

### Phase 3: SMP

- One run queue per core (with work stealing)
- AP (application processor) startup via SIPI
- Per-core scheduler, each core runs its own actor loop
- Lock-free mailboxes become essential (CAS on enqueue)
- Shared immutable data needs no synchronization
- Mutable kernel state (network, etc.) protected by spinlocks

---

## API

### Primitives

```lisp
;; Create a new actor running function f
(spawn f)                        ; => actor-id
(spawn f arg1 arg2)              ; with initial arguments

;; Send a message to an actor
(send actor-id message)          ; async, non-blocking, always succeeds

;; Receive the next message (blocks if mailbox empty)
(receive)                        ; => message
(receive timeout)                ; => message or nil

;; Yield execution to other actors
(yield)

;; Get own actor ID
(self)                           ; => actor-id

;; Link actors (bidirectional failure notification)
(link actor-id)
(unlink actor-id)

;; Monitor an actor (unidirectional)
(monitor actor-id)               ; => monitor-ref

;; Spawn + link in one operation
(spawn-link f)                   ; => actor-id
```

### Pattern Matching on Receive

```lisp
;; Selective receive with pattern matching
(receive-match
  ((list 'ping sender)
   (send sender (list 'pong (self))))
  ((list 'data payload)
   (process payload))
  (timeout 5000 (handle-timeout)))
```

### Supervisors

```lisp
;; Define a supervisor
(defun my-supervisor ()
  (supervisor
    :strategy :one-for-one
    :children
    (list
      (child 'worker-1 #'worker-fn :restart :permanent)
      (child 'worker-2 #'other-fn :restart :transient))))

;; Start it
(spawn #'my-supervisor)
```

---

## Implementation Plan

### Phase 8.1: Context Switching -- DONE

The foundation. Multiple stacks, save/restore execution state.

**Implemented:**
- Actor struct: 128 bytes at 0x05100000+, 1-based IDs (max 64 actors)
- `save-context` / `restore-context`: setjmp/longjmp-style primitives in cross-compile.lisp
- Continuation stored in save area [addr+40], NOT on stack (avoids compiler stack tracking issues)
- Saves RSP, RBX, RBP, R12, R14 (R12/R14 became per-actor in Phase 8.4)
- Primordial actor = ID 1, initialized in `actor-init`
- 64KB stack per actor at 0x05200000 + id * 0x10000

**Actor struct layout (128 bytes):**
```
+0x00 status (0=free, 1=running, 2=ready, 3=dead, 4=blocked)
+0x08 saved RSP
+0x10 saved R12 (cons alloc ptr)
+0x18 saved R14 (cons alloc limit)
+0x20 saved RBX
+0x28 saved RBP
+0x30 continuation (save_area+40)
+0x38 actor-id
+0x40 cons-from-start (for GC semispace tracking)
+0x48 next-in-queue
+0x50 mailbox-head
+0x58 mailbox-tail
+0x60 linked-actor
+0x68 cons-to-start (for GC semispace tracking)
+0x70 obj-alloc (object space allocation pointer)
+0x78 obj-limit (object space limit)
```

### Phase 8.2: Mailboxes and Send/Receive -- DONE

**Implemented:**
- Mailbox: cons-list FIFO per actor (head at +0x50, tail at +0x58)
- `send`: enqueues tagged cons cell, wakes blocked (status=4) receivers
- `receive`: dequeues from mailbox, blocks actor if empty (status=4→scheduler switch)
- `receive-timeout`: non-blocking variant, polls via yield up to N times, returns 0 on timeout
- Messages are fixnums (actor IDs, values). No deep copying yet (shared heap).

### Phase 8.3: Scheduler + Reduction Counting -- DONE

**Implemented:**
- Run queue: linked list via actor +0x48 (next-in-queue)
- `yield`: save-context, enqueue self, dequeue next, restore-context
- `send` auto-wakes blocked receivers (status 4→2, enqueued)
- **Reduction counting**: counter at 0x05102020 (tagged value, init 4000 = 2000 reductions)
- Compiler inserts counter check at every `loop` back-edge (cross-compile.lisp `compile-loop`)
- On counter exhaustion: reset to 4000, call yield, continue loop
- Functions compiled before `yield` skip the counter (bootstrapping)
- `preempt-test`: busy-worker (tight loop) + reply-worker verify preemption works → output "P"

**Scheduler state at 0x05102000:**
```
+0x00 current-actor (u64)
+0x08 actor-count (u64, next available ID)
+0x10 run-head (u64)
+0x18 initialized (u64)
+0x20 reduction counter (u64, tagged)
```

### Phase 8.5: Spawn and Lifecycle -- DONE

**Implemented:**
- `actor-spawn`: allocates struct + stack, pushes actor-exit as return addr, enqueues
- `actor-exit`: marks dead (status=3), sends own ID to linked actor, switches to next
- `link`: bidirectional (sets +0x60 on both actors)
- `spawn-link`: spawn + link in one call
- Erlang-style supervisor: spawns workers via spawn-link, receives exit notifications, restarts (up to N cycles)

**Demos working:**
- `actor-test`: basic spawn + context switch
- `actor-msg-test`: send/receive between actors
- `actor-ping-test`: ping-pong message exchange
- `actor-multi-test`: 3 concurrent actors
- `actor-link-test`: exit notification via link
- `sup-test`: supervisor restarts 3 workers → "WRWRWD"
- `map-reduce-test`: 4 parallel workers compute sum of squares → 204
- `ring-test`: 5-node ring, 10000 token hops
- `timeout-test`: receive-timeout with timeout and success paths → "TP1"
- `preempt-test`: busy-loop actor preempted by reduction counter → "P"

**Historical note:** Before Phase 8.4, all actors shared the heap and
R12/R14 were global. Phase 8.4 made them per-actor with independent heaps.

### Phase 8.4: Per-Actor GC -- DONE

**Implemented:**
- Each actor gets 1MB heap at `0x06000000 + (id-1) * 0x100000`
  - Cons semispace A: 256KB, Cons semispace B: 256KB, Object: 256KB
- R12/R14 saved/restored per actor in context switch
- Object space pointers (obj-alloc, obj-limit) swapped in yield/receive/actor-exit
- Cheney copying GC runs per-actor, triggered inline at cons allocation OOM
- Semispace bounds computed from R14 via XOR trick (no global metadata needed)
- Full stack scan from RSP to actor stack top (not fixed 16 slots)
- Write barrier disabled (full collection, no generational optimization)
- Mailbox shared pool at 0x05300000 (128KB, bump + free list) prevents
  cross-actor GC issues -- mailbox cons cells never live in actor heaps

**Key design decisions:**
- Messages are fixnums (actor IDs, values), not deep-copied S-expressions.
  The shared pool handles mailbox cell allocation/deallocation.
- Object space uses bump allocation only (no GC). Objects (strings, arrays,
  bignums) are never collected. This is acceptable for the current workload.
- GC code is inlined at every cons allocation site (~300 bytes per site)
  rather than being a callable function, avoiding call/return overhead.

**Tests verified:**
- `(gc-test N)`: allocate N reclaimable cons cells, GC runs and reclaims
- `(alloc-test N)`: allocate N live cells, GC runs but can't reclaim → OOM
- `(ring-test)`: 10000 messages through 5-actor ring via shared pool

### Phase 8.6: SMP -- DONE

**Implemented:**
- AP startup: INIT IPI + SIPI to bring up application processors
- Per-core GDT, IDT, TSS, stack, scheduler state (via GS segment for per-CPU data)
- Per-core run queue with per-CPU actor scheduling
- IPI wakeup: idle cores are woken when actors become runnable
- LAPIC timer preemption as backup to reduction counting
- Tested stable on up to 8 CPUs in QEMU
- AP trampoline copied to 0x8000 (real-mode entry point for secondary cores)
- `smp-copy-trampoline`: copies trampoline from kernel image with null-source guard

---

## Design Decisions

### Why Copy Messages (Not Share)?

Sharing requires either:
- Locks (defeats the purpose of actors)
- Immutability enforcement (complex type system)
- Reference counting (overhead, cycles)

Copying is simple, correct, and fast for small messages. For large data,
we'll add an explicit shared-immutable region later. The common case
(small messages between actors) should be optimized for simplicity.

### Why Reduction Counting + Timer Preemption?

Both are implemented. Reduction counting is the primary mechanism:
- Simple: decrement a counter, check at loop back-edges
- Deterministic: same program behaves the same way
- Safe: only yields at known-good points (between Lisp forms)

LAPIC timer preemption is the backup for actors that loop without
function calls or Lisp-level loops (e.g., tight assembly-level
loops in crypto code). The timer sets a flag; the next safe point
checks it and yields.

### Why Not Green Threads + Shared Memory?

Shared memory concurrency is strictly harder to program correctly.
Every concurrent Lisp (SBCL, CCL, LispWorks) struggles with thread
safety in the runtime. The actor model sidesteps this entirely: if
you can't share memory, you can't have data races.

For ASI workloads specifically: agents that communicate by message are
naturally distributable across machines. Shared-memory agents are not.
