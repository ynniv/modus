;;;; GCM (Galois/Counter Mode) for AES
;;;; NIST SP 800-38D




;;; GF(2^128) multiplication for GHASH
;;; Uses the irreducible polynomial x^128 + x^7 + x^2 + x + 1

(defun gcm-xor-block (a b)
  "XOR two 16-byte blocks, storing result in a."
  (dotimes (i 16)
    (setf (aref a i) (logxor (aref a i) (aref b i))))
  a)

(defun gcm-shift-right (block)
  "Shift 128-bit block right by 1 bit."
  (let ((carry 0))
    (dotimes (i 16)
      (let ((new-carry (logand (aref block i) 1)))
        (setf (aref block i) (logior (ash (aref block i) -1)
                                      (ash carry 7)))
        (setf carry new-carry))))
  block)

(defun gcm-mul (x y)
  "Multiply two 16-byte blocks in GF(2^128). Returns new 16-byte array."
  (let ((z (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (v (make-array 16 :element-type '(unsigned-byte 8))))
    ;; Copy y to v
    (dotimes (i 16)
      (setf (aref v i) (aref y i)))
    ;; Multiply
    (dotimes (i 16)
      (let ((xi (aref x i)))
        (dotimes (j 8)
          ;; If bit (7-j) of xi is set, z = z XOR v
          (when (logbitp (- 7 j) xi)
            (dotimes (k 16)
              (setf (aref z k) (logxor (aref z k) (aref v k)))))
          ;; v = v >> 1, with reduction if LSB was 1
          (let ((lsb (logand (aref v 15) 1)))
            (gcm-shift-right v)
            ;; If LSB was 1, XOR with R (0xE1 << 120 = first byte is 0xE1)
            (when (= lsb 1)
              (setf (aref v 0) (logxor (aref v 0) #xe1)))))))
    z))

;;; GHASH function
(defun gcm-ghash (h data)
  "Compute GHASH over data using hash key H. Returns 16-byte tag."
  (let ((y (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (len (length data)))
    ;; Process full blocks
    (do ((i 0 (+ i 16)))
        ((>= i len))
      ;; XOR block into Y
      (dotimes (j 16)
        (when (< (+ i j) len)
          (setf (aref y j) (logxor (aref y j) (aref data (+ i j))))))
      ;; Y = Y * H
      (let ((new-y (gcm-mul y h)))
        (dotimes (j 16)
          (setf (aref y j) (aref new-y j)))))
    y))

;;; Counter increment (32-bit counter in last 4 bytes, big-endian)
(defun gcm-inc32 (counter)
  "Increment the 32-bit counter portion of the counter block (last 4 bytes)."
  ;; Increment byte by byte from LSB to MSB, handling carry
  ;; Written to be compiler-friendly (no complex expressions in setf)
  (let ((b (aref counter 15)))
    (setf b (+ b 1))
    (if (< b 256)
        (setf (aref counter 15) b)
        (progn
          (setf (aref counter 15) 0)
          (setf b (aref counter 14))
          (setf b (+ b 1))
          (if (< b 256)
              (setf (aref counter 14) b)
              (progn
                (setf (aref counter 14) 0)
                (setf b (aref counter 13))
                (setf b (+ b 1))
                (if (< b 256)
                    (setf (aref counter 13) b)
                    (progn
                      (setf (aref counter 13) 0)
                      (setf b (aref counter 12))
                      (setf b (+ b 1))
                      (when (>= b 256) (setf b 0))
                      (setf (aref counter 12) b))))))))
  counter)

;;; AES-GCM encryption
(defun aes-gcm-encrypt (key nonce plaintext aad)
  "Encrypt using AES-GCM. Returns (ciphertext . tag).
   KEY: 16 or 32 bytes, NONCE: 12 bytes, PLAINTEXT/AAD: byte vectors."
  (let* ((key-len (length key))
         (expanded-key (if (= key-len 16)
                           (aes-expand-key-128 key)
                           (aes-expand-key-256 key)))
         (rounds (if (= key-len 16) 10 14))
         ;; Compute H = AES(K, 0^128)
         (zero-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (h (aes-encrypt-block zero-block expanded-key rounds))
         ;; Initialize counter (J0)
         (j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (pt-len (length plaintext))
         (ciphertext (make-array pt-len :element-type '(unsigned-byte 8))))

    ;; Set up J0 from 12-byte nonce: nonce || 0x00000001
    (dotimes (i 12)
      (setf (aref j0 i) (aref nonce i)))
    (setf (aref j0 15) 1)

    ;; Encrypt plaintext using counter mode (starting at J0+1)
    (let ((counter (make-array 16 :element-type '(unsigned-byte 8))))
      (dotimes (i 16)
        (setf (aref counter i) (aref j0 i)))

      (do ((i 0 (+ i 16)))
          ((>= i pt-len))
        (gcm-inc32 counter)
        (let ((keystream (aes-encrypt-block counter expanded-key rounds)))
          (dotimes (j 16)
            (when (< (+ i j) pt-len)
              (setf (aref ciphertext (+ i j))
                    (logxor (aref plaintext (+ i j)) (aref keystream j))))))))

    ;; Compute authentication tag
    ;; Construct data for GHASH: AAD || pad || C || pad || len(AAD) || len(C)
    (let* ((aad-len (length aad))
           (aad-padded-len (* 16 (ceiling aad-len 16)))
           (ct-padded-len (* 16 (ceiling pt-len 16)))
           (ghash-data (make-array (+ aad-padded-len ct-padded-len 16)
                                   :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
      ;; Copy AAD
      (dotimes (i aad-len)
        (setf (aref ghash-data i) (aref aad i)))
      ;; Copy ciphertext
      (dotimes (i pt-len)
        (setf (aref ghash-data (+ aad-padded-len i)) (aref ciphertext i)))
      ;; Length block (AAD length in bits, then CT length in bits, both as 64-bit big-endian)
      (let ((len-offset (+ aad-padded-len ct-padded-len))
            (aad-bits (* aad-len 8))
            (ct-bits (* pt-len 8)))
        ;; AAD length (64-bit, we only use lower 32 bits)
        (setf (aref ghash-data (+ len-offset 4)) (logand (ash aad-bits -24) #xff))
        (setf (aref ghash-data (+ len-offset 5)) (logand (ash aad-bits -16) #xff))
        (setf (aref ghash-data (+ len-offset 6)) (logand (ash aad-bits -8) #xff))
        (setf (aref ghash-data (+ len-offset 7)) (logand aad-bits #xff))
        ;; CT length (64-bit)
        (setf (aref ghash-data (+ len-offset 12)) (logand (ash ct-bits -24) #xff))
        (setf (aref ghash-data (+ len-offset 13)) (logand (ash ct-bits -16) #xff))
        (setf (aref ghash-data (+ len-offset 14)) (logand (ash ct-bits -8) #xff))
        (setf (aref ghash-data (+ len-offset 15)) (logand ct-bits #xff)))

      ;; Compute GHASH
      (let ((s (gcm-ghash h ghash-data)))
        ;; Tag = GHASH XOR AES(K, J0)
        (let ((j0-encrypted (aes-encrypt-block j0 expanded-key rounds)))
          (dotimes (i 16)
            (setf (aref s i) (logxor (aref s i) (aref j0-encrypted i))))
          (cons ciphertext s))))))

;;; AES-GCM decryption
(defun aes-gcm-decrypt (key nonce ciphertext aad tag)
  "Decrypt using AES-GCM. Returns plaintext or NIL if authentication fails.
   KEY: 16 or 32 bytes, NONCE: 12 bytes, TAG: 16 bytes."
  (let* ((key-len (length key))
         (expanded-key (if (= key-len 16)
                           (aes-expand-key-128 key)
                           (aes-expand-key-256 key)))
         (rounds (if (= key-len 16) 10 14))
         ;; Compute H = AES(K, 0^128)
         (zero-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (h (aes-encrypt-block zero-block expanded-key rounds))
         ;; Initialize counter (J0)
         (j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (ct-len (length ciphertext))
         (plaintext (make-array ct-len :element-type '(unsigned-byte 8))))

    ;; Set up J0 from 12-byte nonce
    (dotimes (i 12)
      (setf (aref j0 i) (aref nonce i)))
    (setf (aref j0 15) 1)

    ;; Compute authentication tag first (verify before decrypting)
    (let* ((aad-len (length aad))
           (aad-padded-len (* 16 (ceiling aad-len 16)))
           (ct-padded-len (* 16 (ceiling ct-len 16)))
           (ghash-data (make-array (+ aad-padded-len ct-padded-len 16)
                                   :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
      ;; Copy AAD
      (dotimes (i aad-len)
        (setf (aref ghash-data i) (aref aad i)))
      ;; Copy ciphertext
      (dotimes (i ct-len)
        (setf (aref ghash-data (+ aad-padded-len i)) (aref ciphertext i)))
      ;; Length block
      (let ((len-offset (+ aad-padded-len ct-padded-len))
            (aad-bits (* aad-len 8))
            (ct-bits (* ct-len 8)))
        (setf (aref ghash-data (+ len-offset 4)) (logand (ash aad-bits -24) #xff))
        (setf (aref ghash-data (+ len-offset 5)) (logand (ash aad-bits -16) #xff))
        (setf (aref ghash-data (+ len-offset 6)) (logand (ash aad-bits -8) #xff))
        (setf (aref ghash-data (+ len-offset 7)) (logand aad-bits #xff))
        (setf (aref ghash-data (+ len-offset 12)) (logand (ash ct-bits -24) #xff))
        (setf (aref ghash-data (+ len-offset 13)) (logand (ash ct-bits -16) #xff))
        (setf (aref ghash-data (+ len-offset 14)) (logand (ash ct-bits -8) #xff))
        (setf (aref ghash-data (+ len-offset 15)) (logand ct-bits #xff)))

      ;; Compute GHASH
      (let ((s (gcm-ghash h ghash-data)))
        ;; Expected tag = GHASH XOR AES(K, J0)
        (let ((j0-encrypted (aes-encrypt-block j0 expanded-key rounds)))
          (dotimes (i 16)
            (setf (aref s i) (logxor (aref s i) (aref j0-encrypted i))))
          ;; Verify tag
          (dotimes (i 16)
            (unless (= (aref s i) (aref tag i))
              (return-from aes-gcm-decrypt nil))))))

    ;; Decrypt ciphertext using counter mode
    (let ((counter (make-array 16 :element-type '(unsigned-byte 8))))
      (dotimes (i 16)
        (setf (aref counter i) (aref j0 i)))

      (do ((i 0 (+ i 16)))
          ((>= i ct-len))
        (gcm-inc32 counter)
        (let ((keystream (aes-encrypt-block counter expanded-key rounds)))
          (dotimes (j 16)
            (when (< (+ i j) ct-len)
              (setf (aref plaintext (+ i j))
                    (logxor (aref ciphertext (+ i j)) (aref keystream j))))))))

    plaintext))
