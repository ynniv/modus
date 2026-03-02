;;;; actors-net-overrides.lisp - Actor-aware SSH overrides for AArch64
;;;;
;;;; Loaded LAST (after aarch64-overrides.lisp) to re-override functions
;;;; that need actor-aware behavior instead of single-threaded operation.
;;;;
;;;; Overrides:
;;;;   receive              - yield instead of inline E1000 poll
;;;;   net-actor-main       - yield on idle (cooperative scheduling)
;;;;   net-accept-connection - spawn handler actor instead of inline call
;;;;   ssh-connection-handler - call actor-exit when done

;;; ============================================================
;;; receive: yield to let net-actor-main poll E1000
;;; ============================================================
;;;
;;; In single-threaded mode, receive() polls E1000 inline.
;;; With actors, net-actor-main (actor 2) polls E1000 in its own loop.
;;; SSH handler actors call receive() when waiting for data.
;;; Yield gives net-actor-main CPU time, return 1 so the retry loop continues.

(defun receive ()
  (yield)
  1)

;;; ============================================================
;;; net-actor-main: actor-aware network polling loop
;;; ============================================================
;;;
;;; Same as ip.lisp version but yields on idle instead of busy-waiting.
;;; This allows SSH handler actors to run when no packets arrive.

(defun net-actor-main ()
  (loop
    (io-delay)
    (let ((pkt-len (e1000-receive)))
      (if (zerop pkt-len)
          (yield)
          (let ((buf (e1000-rx-buf)))
            (let ((et-hi (mem-ref (+ buf 12) :u8))
                  (et-lo (mem-ref (+ buf 13) :u8)))
              (if (eq et-hi #x08)
                  (if (eq et-lo #x06)
                      (let ((arp-op (buf-read-u16-mem buf 20)))
                        (when (eq arp-op 1)
                          (arp-reply buf)))
                      (when (eq et-lo 0)
                        (let ((proto (mem-ref (+ buf 23) :u8)))
                          (if (eq proto 1)
                              (icmp-handle buf 14)
                              (when (eq proto 6)
                                (net-handle-tcp buf pkt-len))))))
                  ())))))))

;;; ============================================================
;;; Per-connection handler entry functions
;;; ============================================================
;;;
;;; Each connection handler is a separate function so fn-addr can resolve it.
;;; conn-alloc returns 0-3; actor-spawn-handler dispatches to the right one.
;;; Entry functions MUST NOT return (actors have no return address on stack).

(defun ssh-handler-0 ()
  (ssh-connection-handler 0))

(defun ssh-handler-1 ()
  (ssh-connection-handler 1))

(defun ssh-handler-2 ()
  (ssh-connection-handler 2))

(defun ssh-handler-3 ()
  (ssh-connection-handler 3))

;;; ============================================================
;;; Spawn dispatch (fn-addr requires static function names)
;;; ============================================================

(defun actor-spawn-handler (conn)
  (if (eq conn 0) (actor-spawn (fn-addr ssh-handler-0))
      (if (eq conn 1) (actor-spawn (fn-addr ssh-handler-1))
          (if (eq conn 2) (actor-spawn (fn-addr ssh-handler-2))
              (actor-spawn (fn-addr ssh-handler-3))))))

;;; ============================================================
;;; ssh-connection-handler: actor-aware (calls actor-exit)
;;; ============================================================

(defun ssh-connection-handler (conn)
  (let ((ssh (conn-ssh conn))
        (cb (conn-base conn)))
    (ssh-handle-connection ssh)
    (tcp-close-conn cb)
    (conn-free conn)
    (actor-exit)))

;;; ============================================================
;;; net-accept-connection: spawn handler actor
;;; ============================================================
;;;
;;; Same TCP handshake as aarch64-overrides version, but spawns a
;;; handler actor instead of calling ssh-connection-handler inline.

(defun net-accept-connection (src-ip src-port dst-port buf)
  (let ((conn (conn-alloc)))
    (when (not (= conn (- 0 1)))
      (conn-init conn dst-port src-port src-ip)
      (let ((their-seq (buf-read-u32-mem buf 38)))
        (setf (mem-ref (+ (conn-base conn) #x014) :u32) (+ their-seq 1)))
      ;; Init SSH recv buffer BEFORE net-wait-ack so piggybacked data works
      (let ((ssh (conn-ssh conn)))
        (setf (mem-ref (+ ssh #x6D4) :u32) 0))
      (tcp-send-segment-conn (conn-base conn) 18 (make-array 0) 0)
      (net-wait-ack conn)
      (when (eq (mem-ref (conn-base conn) :u32) 2)
        (ssh-copy-host-key conn)
        (let ((ssh (conn-ssh conn)))
          (setf (mem-ref ssh :u32) 0)
          (setf (mem-ref (+ ssh #x04) :u32) 0)
          (setf (mem-ref (+ ssh #x08) :u32) 0)
          (setf (mem-ref (+ ssh #x0C) :u32) 0)
          (setf (mem-ref (+ ssh #x10) :u32) 0)
          ;; Don't reset 0x6D4 - may already have data from ACK packet
          (setf (mem-ref (+ ssh #x28) :u32) 0)
          (setf (mem-ref (+ ssh #x150) :u32) 0)
          (setf (mem-ref (+ ssh #x154) :u32) 0)
          (setf (mem-ref (+ ssh #x2C) :u32)
                (+ src-port (* src-ip 7))))
        (setf (mem-ref (+ (ssh-ipc-base) #x60448) :u32) conn)
        ;; Spawn handler actor and store its ID for message routing
        (let ((handler-id (actor-spawn-handler conn)))
          (setf (mem-ref (+ (conn-base conn) #x18) :u32) handler-id))))))
