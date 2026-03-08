;;;; HKDF implementation — reference CL implementation (needs MVM adaptation)
;;;; Based on RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function



;;; HKDF consists of two steps:
;;; 1. HKDF-Extract: extract a pseudorandom key from input keying material
;;; 2. HKDF-Expand: expand the pseudorandom key into additional keys

(defun hkdf-extract (salt ikm)
  "HKDF-Extract(salt, IKM) -> PRK
   Extract a pseudorandom key from input keying material.
   SALT: optional salt (if nil, use zeros of hash length)
   IKM: input keying material (byte array)
   Returns: 32-byte pseudorandom key"
  (let ((actual-salt (if (and salt (> (length salt) 0))
                         salt
                         (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 0))))
    (hmac-sha256 actual-salt ikm)))

(defun hkdf-expand (prk info length)
  "HKDF-Expand(PRK, info, L) -> OKM
   Expand pseudorandom key into output keying material.
   PRK: pseudorandom key from HKDF-Extract
   INFO: optional context/application-specific info (byte array or nil)
   LENGTH: desired output length in bytes (max 255 * 32 = 8160)
   Returns: byte array of requested length"
  (let* ((hash-len 32)
         (n (ceiling length hash-len))
         (okm (make-array length :element-type '(unsigned-byte 8)))
         (t-prev (make-array 0 :element-type '(unsigned-byte 8)))
         (info-bytes (or info (make-array 0 :element-type '(unsigned-byte 8))))
         (info-len (length info-bytes)))

    (when (> n 255)
      (error "HKDF-Expand: requested length too long"))

    (dotimes (i n)
      (let* ((counter (1+ i))
             ;; T(i) = HMAC(PRK, T(i-1) || info || counter)
             (input-len (+ (length t-prev) info-len 1))
             (input (make-array input-len :element-type '(unsigned-byte 8)))
             (pos 0))

        ;; Copy T(i-1)
        (dotimes (j (length t-prev))
          (setf (aref input pos) (aref t-prev j))
          (incf pos))

        ;; Copy info
        (dotimes (j info-len)
          (setf (aref input pos) (aref info-bytes j))
          (incf pos))

        ;; Append counter byte
        (setf (aref input pos) counter)

        ;; Compute T(i)
        (setf t-prev (hmac-sha256 prk input))

        ;; Copy T(i) to output (only what's needed for last block)
        (let* ((offset (* i hash-len))
               (copy-len (min hash-len (- length offset))))
          (dotimes (j copy-len)
            (setf (aref okm (+ offset j)) (aref t-prev j))))))

    okm))

(defun hkdf (salt ikm info length)
  "HKDF: Combined Extract-and-Expand.
   Returns output keying material of requested length."
  (let ((prk (hkdf-extract salt ikm)))
    (hkdf-expand prk info length)))

;;; SHA-384 variants for TLS_AES_256_GCM_SHA384

(defun hkdf-extract-384 (salt ikm)
  "HKDF-Extract with SHA-384. Returns 48-byte pseudorandom key."
  (let ((actual-salt (if (and salt (> (length salt) 0))
                         salt
                         (make-array 48 :element-type '(unsigned-byte 8)
                                     :initial-element 0))))
    (hmac-sha384 actual-salt ikm)))

(defun hkdf-expand-384 (prk info length)
  "HKDF-Expand with SHA-384. PRK should be 48 bytes."
  (let* ((hash-len 48)
         (n (ceiling length hash-len))
         (okm (make-array length :element-type '(unsigned-byte 8)))
         (t-prev (make-array 0 :element-type '(unsigned-byte 8)))
         (info-bytes (or info (make-array 0 :element-type '(unsigned-byte 8))))
         (info-len (length info-bytes)))

    (when (> n 255)
      (error "HKDF-Expand-384: requested length too long"))

    (dotimes (i n)
      (let* ((counter (1+ i))
             (input-len (+ (length t-prev) info-len 1))
             (input (make-array input-len :element-type '(unsigned-byte 8)))
             (pos 0))

        ;; Copy T(i-1)
        (dotimes (j (length t-prev))
          (setf (aref input pos) (aref t-prev j))
          (incf pos))

        ;; Copy info
        (dotimes (j info-len)
          (setf (aref input pos) (aref info-bytes j))
          (incf pos))

        ;; Append counter byte
        (setf (aref input pos) counter)

        ;; Compute T(i)
        (setf t-prev (hmac-sha384 prk input))

        ;; Copy T(i) to output
        (let* ((offset (* i hash-len))
               (copy-len (min hash-len (- length offset))))
          (dotimes (j copy-len)
            (setf (aref okm (+ offset j)) (aref t-prev j))))))

    okm))

;;; TLS 1.3 specific functions

(defun tls13-hkdf-expand-label (secret label context length)
  "TLS 1.3 HKDF-Expand-Label function.
   SECRET: PRK
   LABEL: string label (without 'tls13 ' prefix)
   CONTEXT: byte array context (hash transcript, etc.)
   LENGTH: desired output length"
  (let* ((full-label-str (concatenate 'string "tls13 " label))
         (label-len (length full-label-str))
         (context-len (if context (length context) 0))
         ;; HkdfLabel = length (2) || label-length (1) || label || context-length (1) || context
         (info-len (+ 2 1 label-len 1 context-len))
         (info (make-array info-len :element-type '(unsigned-byte 8)))
         (pos 0))

    ;; Length (2 bytes, big-endian)
    (setf (aref info pos) (ash length -8))
    (incf pos)
    (setf (aref info pos) (logand length #xff))
    (incf pos)

    ;; Label length (1 byte)
    (setf (aref info pos) label-len)
    (incf pos)

    ;; Label bytes
    (dotimes (i label-len)
      (setf (aref info pos) (char-code (char full-label-str i)))
      (incf pos))

    ;; Context length (1 byte)
    (setf (aref info pos) context-len)
    (incf pos)

    ;; Context bytes
    (when context
      (dotimes (i context-len)
        (setf (aref info pos) (aref context i))
        (incf pos)))

    (hkdf-expand secret info length)))

(defun tls13-derive-secret (secret label messages)
  "TLS 1.3 Derive-Secret function.
   Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)"
  (tls13-hkdf-expand-label secret label messages 32))

;;; TLS 1.3 SHA-384 variants

(defun tls13-hkdf-expand-label-384 (secret label context length)
  "TLS 1.3 HKDF-Expand-Label with SHA-384."
  (let* ((full-label-str (concatenate 'string "tls13 " label))
         (label-len (length full-label-str))
         (context-len (if context (length context) 0))
         (info-len (+ 2 1 label-len 1 context-len))
         (info (make-array info-len :element-type '(unsigned-byte 8)))
         (pos 0))

    ;; Length (2 bytes, big-endian)
    (setf (aref info pos) (ash length -8))
    (incf pos)
    (setf (aref info pos) (logand length #xff))
    (incf pos)

    ;; Label length (1 byte)
    (setf (aref info pos) label-len)
    (incf pos)

    ;; Label bytes
    (dotimes (i label-len)
      (setf (aref info pos) (char-code (char full-label-str i)))
      (incf pos))

    ;; Context length (1 byte)
    (setf (aref info pos) context-len)
    (incf pos)

    ;; Context bytes
    (when context
      (dotimes (i context-len)
        (setf (aref info pos) (aref context i))
        (incf pos)))

    (hkdf-expand-384 secret info length)))

(defun tls13-derive-secret-384 (secret label messages)
  "TLS 1.3 Derive-Secret with SHA-384. Returns 48-byte secret."
  (tls13-hkdf-expand-label-384 secret label messages 48))

;;; Test function
(defun hkdf-test ()
  "Test HKDF with RFC 5869 test vectors."
  (format t "~&HKDF test:~%")

  ;; Test Case 1 from RFC 5869
  ;; IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
  ;; salt = 0x000102030405060708090a0b0c (13 octets)
  ;; info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
  ;; L = 42
  ;; PRK = 077709362c2e32df0ddc3f0dc47bba63
  ;;       90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
  ;; OKM = 3cb25f25faacd57a90434f64d0362f2a
  ;;       2d2d0a90cf1a5a4c5db02d56ecc4c5bf
  ;;       34007208d5b887185865 (42 octets)

  (let* ((ikm (make-array 22 :element-type '(unsigned-byte 8) :initial-element #x0b))
         (salt (make-array 13 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x00 #x01 #x02 #x03 #x04 #x05 #x06
                                               #x07 #x08 #x09 #x0a #x0b #x0c)))
         (info (make-array 10 :element-type '(unsigned-byte 8)
                           :initial-contents '(#xf0 #xf1 #xf2 #xf3 #xf4 #xf5 #xf6
                                               #xf7 #xf8 #xf9)))
         (prk (hkdf-extract salt ikm))
         (okm (hkdf-expand prk info 42)))

    (format t "  PRK: ")
    (dotimes (i 8)
      (format t "~2,'0x" (aref prk i)))
    (format t "...~%")
    ;; Expected PRK starts with: 077709362c2e32df

    (format t "  OKM: ")
    (dotimes (i 8)
      (format t "~2,'0x" (aref okm i)))
    (format t "...~%")
    ;; Expected OKM starts with: 3cb25f25faacd57a

    (when (and (= (aref prk 0) #x07)
               (= (aref prk 1) #x77)
               (= (aref okm 0) #x3c)
               (= (aref okm 1) #xb2))
      (format t "  Test 1: PASS~%")))

  t)
