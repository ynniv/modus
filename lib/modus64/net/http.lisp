;;;; http.lisp - HTTP/1.0 server for bare-metal Modus64
;;;;
;;;; Minimal HTTP server on port 80. One request-response per connection.
;;;; Shares connection slots (0-3) with SSH; protocol determined by dst-port.
;;;;
;;;; conn-base+0x1C: protocol type (0=SSH, 1=HTTP)
;;;; Recv buffer at conn-ssh+0x6D4 (length) / conn-ssh+0x6D8 (data)

;;; ============================================================
;;; HTTP response builder
;;; ============================================================

(defun http-write-dec (arr pos n)
  ;; Write decimal number into byte array, return new position
  (if (< n 10)
      (progn (aset arr pos (+ 48 n))
             (+ pos 1))
      (let ((q (/ n 10)))
        (let ((r (- n (* q 10))))
          (let ((p2 (http-write-dec arr pos q)))
            (aset arr p2 (+ 48 r))
            (+ p2 1))))))

(defun http-build-response (body body-len)
  ;; Build complete HTTP/1.0 response as a byte array.
  ;; Header: "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: NNN\r\n\r\n"
  ;; Returns (cons array total-length)
  (let ((arr (make-array 1400)))
    (let ((p 0))
      ;; "HTTP/1.0 200 OK\r\n"
      (aset arr 0 72) (aset arr 1 84) (aset arr 2 84) (aset arr 3 80)
      (aset arr 4 47) (aset arr 5 49) (aset arr 6 46) (aset arr 7 48)
      (aset arr 8 32) (aset arr 9 50) (aset arr 10 48) (aset arr 11 48)
      (aset arr 12 32) (aset arr 13 79) (aset arr 14 75) (aset arr 15 13)
      (aset arr 16 10)
      (setq p 17)
      ;; "Content-Type: text/html\r\n"
      (aset arr 17 67) (aset arr 18 111) (aset arr 19 110) (aset arr 20 116)
      (aset arr 21 101) (aset arr 22 110) (aset arr 23 116) (aset arr 24 45)
      (aset arr 25 84) (aset arr 26 121) (aset arr 27 112) (aset arr 28 101)
      (aset arr 29 58) (aset arr 30 32)
      (aset arr 31 116) (aset arr 32 101) (aset arr 33 120) (aset arr 34 116)
      (aset arr 35 47) (aset arr 36 104) (aset arr 37 116) (aset arr 38 109)
      (aset arr 39 108)
      (aset arr 40 13) (aset arr 41 10)
      (setq p 42)
      ;; "Content-Length: "
      (aset arr 42 67) (aset arr 43 111) (aset arr 44 110) (aset arr 45 116)
      (aset arr 46 101) (aset arr 47 110) (aset arr 48 116) (aset arr 49 45)
      (aset arr 50 76) (aset arr 51 101) (aset arr 52 110) (aset arr 53 103)
      (aset arr 54 116) (aset arr 55 104) (aset arr 56 58) (aset arr 57 32)
      (setq p (http-write-dec arr 58 body-len))
      ;; "\r\n\r\n"
      (aset arr p 13) (aset arr (+ p 1) 10)
      (aset arr (+ p 2) 13) (aset arr (+ p 3) 10)
      (setq p (+ p 4))
      ;; Copy body
      (let ((i 0))
        (loop
          (when (>= i body-len) (return 0))
          (aset arr (+ p i) (aref body i))
          (setq i (+ i 1))))
      (cons arr (+ p body-len)))))

(defun http-build-404 ()
  ;; "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"
  (let ((arr (make-array 48)))
    (aset arr 0 72) (aset arr 1 84) (aset arr 2 84) (aset arr 3 80)
    (aset arr 4 47) (aset arr 5 49) (aset arr 6 46) (aset arr 7 48)
    (aset arr 8 32) (aset arr 9 52) (aset arr 10 48) (aset arr 11 52)
    (aset arr 12 32) (aset arr 13 78) (aset arr 14 111) (aset arr 15 116)
    (aset arr 16 32) (aset arr 17 70) (aset arr 18 111) (aset arr 19 117)
    (aset arr 20 110) (aset arr 21 100) (aset arr 22 13) (aset arr 23 10)
    ;; "Content-Length: 0\r\n\r\n"
    (aset arr 24 67) (aset arr 25 111) (aset arr 26 110) (aset arr 27 116)
    (aset arr 28 101) (aset arr 29 110) (aset arr 30 116) (aset arr 31 45)
    (aset arr 32 76) (aset arr 33 101) (aset arr 34 110) (aset arr 35 103)
    (aset arr 36 116) (aset arr 37 104) (aset arr 38 58) (aset arr 39 32)
    (aset arr 40 48) (aset arr 41 13) (aset arr 42 10) (aset arr 43 13)
    (aset arr 44 10)
    (cons arr 45)))

;;; ============================================================
;;; HTML body for GET /
;;; ============================================================

(defun http-build-index-body ()
  ;; "<html><body><h1>modus64</h1><p>Pi Zero 2 W bare-metal Lisp</p></body></html>"
  ;; Returns (cons array length)
  (let ((arr (make-array 80)))
    ;; <html><body><h1>modus64</h1><p>Pi Zero 2 W bare-metal Lisp</p></body></html>
    (aset arr 0 60) (aset arr 1 104) (aset arr 2 116) (aset arr 3 109)
    (aset arr 4 108) (aset arr 5 62)          ;; <html>
    (aset arr 6 60) (aset arr 7 98) (aset arr 8 111) (aset arr 9 100)
    (aset arr 10 121) (aset arr 11 62)        ;; <body>
    (aset arr 12 60) (aset arr 13 104) (aset arr 14 49) (aset arr 15 62)  ;; <h1>
    (aset arr 16 109) (aset arr 17 111) (aset arr 18 100) (aset arr 19 117)
    (aset arr 20 115) (aset arr 21 54) (aset arr 22 52)  ;; modus64
    (aset arr 23 60) (aset arr 24 47) (aset arr 25 104) (aset arr 26 49)
    (aset arr 27 62)                          ;; </h1>
    (aset arr 28 60) (aset arr 29 112) (aset arr 30 62)  ;; <p>
    ;; Pi Zero 2 W bare-metal Lisp
    (aset arr 31 80) (aset arr 32 105) (aset arr 33 32) (aset arr 34 90)
    (aset arr 35 101) (aset arr 36 114) (aset arr 37 111) (aset arr 38 32)
    (aset arr 39 50) (aset arr 40 32) (aset arr 41 87) (aset arr 42 32)
    (aset arr 43 98) (aset arr 44 97) (aset arr 45 114) (aset arr 46 101)
    (aset arr 47 45) (aset arr 48 109) (aset arr 49 101) (aset arr 50 116)
    (aset arr 51 97) (aset arr 52 108) (aset arr 53 32)
    (aset arr 54 76) (aset arr 55 105) (aset arr 56 115) (aset arr 57 112)
    (aset arr 58 60) (aset arr 59 47) (aset arr 60 112) (aset arr 61 62)  ;; </p>
    (aset arr 62 60) (aset arr 63 47) (aset arr 64 98) (aset arr 65 111)
    (aset arr 66 100) (aset arr 67 121) (aset arr 68 62)  ;; </body>
    (aset arr 69 60) (aset arr 70 47) (aset arr 71 104) (aset arr 72 116)
    (aset arr 73 109) (aset arr 74 108) (aset arr 75 62)  ;; </html>
    (cons arr 76)))

;;; ============================================================
;;; HTTP request handling
;;; ============================================================

(defun http-connection-handler (conn)
  ;; Wait for HTTP request, send response, close connection.
  (let ((ssh (conn-ssh conn))
        (cb (conn-base conn)))
    ;; Wait for request data
    (let ((tries 0))
      (loop
        (when (> tries 500) (return 0))
        (when (> (mem-ref (+ ssh #x6D4) :u32) 0) (return 0))
        (yield)
        (setq tries (+ tries 1))))
    ;; Check we have data
    (let ((blen (mem-ref (+ ssh #x6D4) :u32)))
      (when (> blen 3)
        ;; Check for "GET " at start of recv buffer
        (let ((b0 (mem-ref (+ ssh #x6D8) :u8))
              (b1 (mem-ref (+ (+ ssh #x6D8) 1) :u8))
              (b2 (mem-ref (+ (+ ssh #x6D8) 2) :u8))
              (b3 (mem-ref (+ (+ ssh #x6D8) 3) :u8)))
          (if (eq b0 71)  ;; G
              (if (eq b1 69)  ;; E
                  (if (eq b2 84)  ;; T
                      (if (eq b3 32)  ;; space
                          (http-handle-get conn cb ssh blen)
                          (http-send-and-close cb (http-build-404)))
                      (http-send-and-close cb (http-build-404)))
                  (http-send-and-close cb (http-build-404)))
              (http-send-and-close cb (http-build-404))))))
    ;; Close connection
    (tcp-close-conn cb)
    (conn-free conn)
    (actor-exit)))

(defun http-handle-get (conn cb ssh blen)
  ;; Parse path after "GET " — check byte at offset 4
  (let ((path-byte (mem-ref (+ (+ ssh #x6D8) 4) :u8)))
    (if (eq path-byte 47)  ;; /
        ;; Check if it's just "/" (next byte is space or HTTP)
        (let ((next (mem-ref (+ (+ ssh #x6D8) 5) :u8)))
          (if (eq next 32)  ;; "GET / HTTP..."
              (let ((body (http-build-index-body)))
                (let ((resp (http-build-response (car body) (cdr body))))
                  (http-send-and-close cb resp)))
              (if (eq next 72)  ;; "GET /H..." — also treat as index
                  (let ((body (http-build-index-body)))
                    (let ((resp (http-build-response (car body) (cdr body))))
                      (http-send-and-close cb resp)))
                  ;; Other paths → 404
                  (http-send-and-close cb (http-build-404)))))
        (http-send-and-close cb (http-build-404)))))

(defun http-send-and-close (cb resp)
  ;; resp = (cons array length) from http-build-response/http-build-404
  (tcp-send-conn cb (car resp) (cdr resp)))
