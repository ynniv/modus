;;;; WebSocket client implementation (RFC 6455)
;;;; For connecting to Nostr relays and other WebSocket servers


;;; WebSocket opcodes
(defconstant +ws-opcode-continuation+ #x0)
(defconstant +ws-opcode-text+ #x1)
(defconstant +ws-opcode-binary+ #x2)
(defconstant +ws-opcode-close+ #x8)
(defconstant +ws-opcode-ping+ #x9)
(defconstant +ws-opcode-pong+ #xA)

;;; WebSocket connection state
(defun make-ws-connection (conn host &key (secure t))
  "Create a WebSocket connection state wrapping a TLS or TCP connection."
  (list :conn conn
        :tls (if secure conn nil)  ; backward compat
        :host host
        :secure secure
        :state :connecting
        :recv-buffer #()))

(defun ws-get (conn key)
  (getf conn key))

(defun ws-set (conn key value)
  (setf (getf conn key) value))

;;; Base64 encoding/decoding (needed for WebSocket and NIP-04)
(defparameter *base64-alphabet* "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-encode (bytes)
  "Encode bytes to base64 string."
  (let* ((alphabet *base64-alphabet*)
         (len (length bytes))
         (out-len (* 4 (ceiling len 3)))
         (result (make-array out-len :element-type 'character :initial-element #\=))
         (out-pos 0))
    (do ((i 0 (+ i 3)))
        ((>= i len))
      (let* ((b0 (aref bytes i))
             (b1 (if (< (1+ i) len) (aref bytes (1+ i)) 0))
             (b2 (if (< (+ i 2) len) (aref bytes (+ i 2)) 0))
             (triple (logior (ash b0 16) (ash b1 8) b2)))
        (setf (aref result out-pos) (aref alphabet (logand (ash triple -18) #x3f)))
        (incf out-pos)
        (setf (aref result out-pos) (aref alphabet (logand (ash triple -12) #x3f)))
        (incf out-pos)
        (when (< (1+ i) len)
          (setf (aref result out-pos) (aref alphabet (logand (ash triple -6) #x3f))))
        (incf out-pos)
        (when (< (+ i 2) len)
          (setf (aref result out-pos) (aref alphabet (logand triple #x3f))))
        (incf out-pos)))
    (coerce result 'string)))

(defun base64-char-value (c)
  "Get numeric value of base64 character."
  (cond
    ((and (char>= c #\A) (char<= c #\Z)) (- (char-code c) (char-code #\A)))
    ((and (char>= c #\a) (char<= c #\z)) (+ 26 (- (char-code c) (char-code #\a))))
    ((and (char>= c #\0) (char<= c #\9)) (+ 52 (- (char-code c) (char-code #\0))))
    ((char= c #\+) 62)
    ((char= c #\/) 63)
    ((char= c #\=) 0)  ; padding
    (t 0)))

(defun base64-decode (str)
  "Decode base64 string to byte array."
  (let* ((len (length str))
         ;; Remove padding from length calculation
         (pad-count (cond ((and (> len 0) (char= (char str (1- len)) #\=))
                           (if (and (> len 1) (char= (char str (- len 2)) #\=)) 2 1))
                          (t 0)))
         (out-len (- (* 3 (floor len 4)) pad-count))
         (result (make-array out-len :element-type '(unsigned-byte 8)))
         (out-pos 0))
    (do ((i 0 (+ i 4)))
        ((>= i len))
      (let* ((v0 (base64-char-value (char str i)))
             (v1 (base64-char-value (char str (+ i 1))))
             (v2 (if (< (+ i 2) len) (base64-char-value (char str (+ i 2))) 0))
             (v3 (if (< (+ i 3) len) (base64-char-value (char str (+ i 3))) 0))
             (triple (logior (ash v0 18) (ash v1 12) (ash v2 6) v3)))
        (when (< out-pos out-len)
          (setf (aref result out-pos) (logand (ash triple -16) #xff))
          (incf out-pos))
        (when (< out-pos out-len)
          (setf (aref result out-pos) (logand (ash triple -8) #xff))
          (incf out-pos))
        (when (< out-pos out-len)
          (setf (aref result out-pos) (logand triple #xff))
          (incf out-pos))))
    result))

;;; WebSocket handshake
(defun ws-generate-key ()
  "Generate a random 16-byte key and return its base64 encoding."
  (let ((key (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref key i) (random 256)))
    (base64-encode key)))

(defun ws-build-handshake (host path key)
  "Build the WebSocket upgrade request."
  ;; Include User-Agent and Accept headers to look more like a browser
  (format nil "GET ~a HTTP/1.1~c~cHost: ~a~c~cUser-Agent: Mozilla/5.0 (compatible; Modus/1.0)~c~cAccept: */*~c~cUpgrade: websocket~c~cConnection: Upgrade~c~cSec-WebSocket-Key: ~a~c~cSec-WebSocket-Version: 13~c~c~c~c"
          path
          #\return #\newline
          host
          #\return #\newline
          #\return #\newline
          #\return #\newline
          #\return #\newline
          #\return #\newline
          key
          #\return #\newline
          #\return #\newline
          #\return #\newline))

(defun ws-parse-response-line (data start)
  "Parse HTTP response line, return (status-code . end-position) or nil."
  (let ((len (length data))
        (pos start)
        (line-end nil))
    ;; Find end of line
    (loop while (< pos (1- len)) do
      (when (and (= (aref data pos) 13)      ; CR
                 (= (aref data (1+ pos)) 10)) ; LF
        (setf line-end pos)
        (return))
      (incf pos))
    (unless line-end
      (return-from ws-parse-response-line nil))

    ;; Parse "HTTP/1.1 101 ..."
    ;; Find first space, then parse status code
    (setf pos start)
    (loop while (and (< pos line-end) (/= (aref data pos) 32)) do (incf pos))
    (when (>= pos line-end)
      (return-from ws-parse-response-line nil))
    (incf pos) ; skip space

    ;; Parse 3-digit status code
    (let ((status 0))
      (dotimes (i 3)
        (when (>= pos line-end)
          (return-from ws-parse-response-line nil))
        (let ((c (aref data pos)))
          (unless (and (>= c 48) (<= c 57))
            (return-from ws-parse-response-line nil))
          (setf status (+ (* status 10) (- c 48)))
          (incf pos)))
      (cons status (+ line-end 2)))))

(defun ws-find-header-end (data)
  "Find the end of HTTP headers (double CRLF). Returns position after headers or nil."
  (let ((len (length data)))
    (loop for i from 0 to (- len 4) do
      (when (and (= (aref data i) 13)
                 (= (aref data (+ i 1)) 10)
                 (= (aref data (+ i 2)) 13)
                 (= (aref data (+ i 3)) 10))
        (return-from ws-find-header-end (+ i 4))))
    nil))

(defun ws-connect-once (host port path timeout &key (secure t))
  "Single WebSocket connection attempt. Returns connection or nil."
  (let ((conn (if secure
                  (tls-connect host port :timeout timeout)
                  (muerte.x86-pc.e1000::tcp-connect (resolve-hostname host) port :timeout timeout))))
    (unless conn
      (format t "WS: Failed to establish ~a connection~%" (if secure "TLS" "TCP"))
      (return-from ws-connect-once nil))

    ;; Create WebSocket connection
    (let* ((ws (make-ws-connection conn host :secure secure))
           (key (ws-generate-key))
           (request (ws-build-handshake host path key))
           (request-bytes (map 'vector #'char-code request)))

      ;; Send handshake
      (if secure
          (tls-send conn request-bytes)
          (muerte.x86-pc.e1000::tcp-send conn request-bytes))

      ;; Receive response
      (let ((response (if secure
                          (tls-receive conn :timeout timeout)
                          (muerte.x86-pc.e1000::tcp-receive conn :timeout timeout))))
        (unless response
          (if secure (tls-close conn) (muerte.x86-pc.e1000::tcp-close conn))
          (return-from ws-connect-once nil))

        (format t "WS: Got ~d bytes response~%" (length response))

        ;; Parse response status
        (let ((parsed (ws-parse-response-line response 0)))
          (unless parsed
            (format t "WS: Failed to parse response~%")
            (if secure (tls-close conn) (muerte.x86-pc.e1000::tcp-close conn))
            (return-from ws-connect-once nil))

          (let ((status (car parsed)))
            (format t "WS: Status ~d~%" status)
            (unless (= status 101)
              (format t "WS: Expected 101 Switching Protocols, got ~d~%" status)
              ;; Print response for debugging
              (dotimes (i (min 200 (length response)))
                (let ((c (aref response i)))
                  (when (and (>= c 32) (<= c 126))
                    (write-char (code-char c)))))
              (if secure (tls-close conn) (muerte.x86-pc.e1000::tcp-close conn))
              (return-from ws-connect-once nil))

            ;; Find end of headers
            (let ((header-end (ws-find-header-end response)))
              (when header-end
                ;; Save any data after headers as WebSocket frames
                (when (< header-end (length response))
                  (ws-set ws :recv-buffer (subseq response header-end)))))

            ;; Connection established
            (ws-set ws :state :open)
            (format t "WS: Connection established~%")
            ws))))))

(defvar *ws-delay-counter* 0 "Counter to prevent delay optimization")

(defun ws-connect (host &key (port nil) (path "/") (timeout 50) (retries 5) (secure nil secure-supplied))
  "Connect to a WebSocket server with retry logic.
   If secure is not specified, defaults based on port (443=secure, else insecure).
   Returns a WebSocket connection or nil."
  ;; Determine security mode
  (let* ((effective-port (or port (if (and (not secure-supplied) (not secure)) 80 443)))
         (effective-secure (if secure-supplied secure (= effective-port 443))))
    (format t "WS: Connecting to ~a:~d~a (~a)~%"
            host effective-port path (if effective-secure "wss" "ws"))
    (loop for attempt from 1 to retries do
      (format t "WS: Attempt ~d/~d~%" attempt retries)
      (let ((conn (ws-connect-once host effective-port path timeout :secure effective-secure)))
        (when conn
          (return-from ws-connect conn))
        ;; Brief delay before retry - minimal to avoid test timeout
        (when (< attempt retries)
          (format t "WS: Retrying...~%")
          ;; Short delay loop
          (dotimes (i 500000)
            (incf *ws-delay-counter*)))))
    (format t "WS: All ~d attempts failed~%" retries)
    nil))

;;; WebSocket frame handling

(defun ws-build-frame (opcode payload &key (fin t))
  "Build a WebSocket frame. Client frames are always masked."
  (let* ((payload-len (length payload))
         (mask (make-array 4 :element-type '(unsigned-byte 8)))
         (header-len (cond
                       ((<= payload-len 125) 2)
                       ((<= payload-len 65535) 4)
                       (t 10)))
         (frame-len (+ header-len 4 payload-len))  ; +4 for mask
         (frame (make-array frame-len :element-type '(unsigned-byte 8)))
         (pos 0))

    ;; Generate mask
    (dotimes (i 4)
      (setf (aref mask i) (random 256)))

    ;; First byte: FIN + opcode
    (setf (aref frame pos) (logior (if fin #x80 0) (logand opcode #x0f)))
    (incf pos)

    ;; Second byte: MASK bit + payload length
    (cond
      ((<= payload-len 125)
       (setf (aref frame pos) (logior #x80 payload-len))
       (incf pos))
      ((<= payload-len 65535)
       (setf (aref frame pos) (logior #x80 126))
       (incf pos)
       (setf (aref frame pos) (logand (ash payload-len -8) #xff))
       (incf pos)
       (setf (aref frame pos) (logand payload-len #xff))
       (incf pos))
      (t
       (setf (aref frame pos) (logior #x80 127))
       (incf pos)
       ;; 8 bytes for length (we only use lower 32 bits)
       (dotimes (i 4)
         (setf (aref frame pos) 0)
         (incf pos))
       (setf (aref frame pos) (logand (ash payload-len -24) #xff))
       (incf pos)
       (setf (aref frame pos) (logand (ash payload-len -16) #xff))
       (incf pos)
       (setf (aref frame pos) (logand (ash payload-len -8) #xff))
       (incf pos)
       (setf (aref frame pos) (logand payload-len #xff))
       (incf pos)))

    ;; Mask
    (dotimes (i 4)
      (setf (aref frame pos) (aref mask i))
      (incf pos))

    ;; Masked payload
    (dotimes (i payload-len)
      (setf (aref frame pos) (logxor (aref payload i) (aref mask (mod i 4))))
      (incf pos))

    frame))

(defun ws-parse-frame (data)
  "Parse a WebSocket frame from data. Returns (opcode payload remaining-data) or nil if incomplete."
  (when (< (length data) 2)
    (return-from ws-parse-frame nil))

  (let* ((b0 (aref data 0))
         (b1 (aref data 1))
         (fin (logbitp 7 b0))
         (opcode (logand b0 #x0f))
         (masked (logbitp 7 b1))
         (payload-len (logand b1 #x7f))
         (pos 2))

    ;; Extended payload length
    (cond
      ((= payload-len 126)
       (when (< (length data) 4)
         (return-from ws-parse-frame nil))
       (setf payload-len (logior (ash (aref data 2) 8) (aref data 3)))
       (setf pos 4))
      ((= payload-len 127)
       (when (< (length data) 10)
         (return-from ws-parse-frame nil))
       ;; Only use lower 32 bits
       (setf payload-len (logior (ash (aref data 6) 24)
                                 (ash (aref data 7) 16)
                                 (ash (aref data 8) 8)
                                 (aref data 9)))
       (setf pos 10)))

    ;; Mask (server->client should not be masked, but handle it anyway)
    (let ((mask nil))
      (when masked
        (when (< (length data) (+ pos 4))
          (return-from ws-parse-frame nil))
        (setf mask (subseq data pos (+ pos 4)))
        (incf pos 4))

      ;; Check we have full payload
      (when (< (length data) (+ pos payload-len))
        (return-from ws-parse-frame nil))

      ;; Extract payload
      (let ((payload (make-array payload-len :element-type '(unsigned-byte 8))))
        (dotimes (i payload-len)
          (let ((b (aref data (+ pos i))))
            (when mask
              (setf b (logxor b (aref mask (mod i 4)))))
            (setf (aref payload i) b)))

        ;; Return opcode, payload, and remaining data
        (let ((remaining (subseq data (+ pos payload-len))))
          (list opcode payload remaining fin))))))

;;; Hostname resolution helper

(defun resolve-hostname (host)
  "Resolve hostname to IP address vector. If already an IP, parse it."
  (cond
    ;; Already a vector (IP address)
    ((vectorp host) host)
    ;; String that looks like an IP address (contains dots and numbers only)
    ((and (stringp host)
          (every (lambda (c) (or (digit-char-p c) (char= c #\.))) host))
     ;; Parse "a.b.c.d" to #(a b c d)
     (let ((parts nil)
           (current 0))
       (loop for c across host do
         (if (char= c #\.)
             (progn (push current parts) (setf current 0))
             (setf current (+ (* current 10) (digit-char-p c)))))
       (push current parts)
       (coerce (nreverse parts) 'vector)))
    ;; Hostname - use DNS
    ((stringp host)
     (muerte.x86-pc.e1000::dns-resolve host))
    (t (error "Invalid host: ~a" host))))

;;; Low-level send/receive helpers (work with both TLS and TCP)

(defun ws-raw-send (conn data)
  "Send raw data through the connection (TLS or TCP)."
  (if (ws-get conn :secure)
      (tls-send (ws-get conn :conn) data)
      (muerte.x86-pc.e1000::tcp-send (ws-get conn :conn) data)))

(defun ws-raw-receive (conn &key (timeout 30))
  "Receive raw data from the connection (TLS or TCP)."
  (if (ws-get conn :secure)
      (tls-receive (ws-get conn :conn) :timeout timeout)
      (muerte.x86-pc.e1000::tcp-receive (ws-get conn :conn) :timeout timeout)))

(defun ws-raw-close (conn)
  "Close the underlying connection (TLS or TCP)."
  (if (ws-get conn :secure)
      (tls-close (ws-get conn :conn))
      (muerte.x86-pc.e1000::tcp-close (ws-get conn :conn))))

;;; High-level WebSocket API

(defun ws-send-text (conn message)
  "Send a text message over WebSocket."
  (let* ((payload (map 'vector #'char-code message))
         (frame (ws-build-frame +ws-opcode-text+ payload)))
    (ws-raw-send conn frame)))

(defun ws-send-binary (conn data)
  "Send binary data over WebSocket."
  (let ((frame (ws-build-frame +ws-opcode-binary+ data)))
    (ws-raw-send conn frame)))

(defun ws-send-ping (conn &optional (data #()))
  "Send a ping frame."
  (let ((frame (ws-build-frame +ws-opcode-ping+ data)))
    (ws-raw-send conn frame)))

(defun ws-send-pong (conn &optional (data #()))
  "Send a pong frame."
  (let ((frame (ws-build-frame +ws-opcode-pong+ data)))
    (ws-raw-send conn frame)))

(defun ws-send-close (conn &optional (code 1000) (reason ""))
  "Send a close frame."
  (let* ((reason-bytes (map 'vector #'char-code reason))
         (payload (make-array (+ 2 (length reason-bytes)) :element-type '(unsigned-byte 8))))
    ;; Close code (2 bytes, big-endian)
    (setf (aref payload 0) (logand (ash code -8) #xff))
    (setf (aref payload 1) (logand code #xff))
    ;; Reason
    (dotimes (i (length reason-bytes))
      (setf (aref payload (+ 2 i)) (aref reason-bytes i)))
    (let ((frame (ws-build-frame +ws-opcode-close+ payload)))
      (ws-raw-send conn frame))
    (ws-set conn :state :closing)))

(defun ws-receive (conn &key (timeout 30))
  "Receive a WebSocket message. Returns (opcode . payload) or nil."
  (let ((buffer (or (ws-get conn :recv-buffer) #())))

    ;; Try to parse a frame from buffer
    (loop
      (let ((parsed (ws-parse-frame buffer)))
        (when parsed
          (let ((opcode (first parsed))
                (payload (second parsed))
                (remaining (third parsed)))
            (ws-set conn :recv-buffer remaining)

            ;; Handle control frames
            (cond
              ((= opcode +ws-opcode-ping+)
               ;; Auto-respond to ping
               (ws-send-pong conn payload)
               ;; Continue to get next frame
               (setf buffer remaining))

              ((= opcode +ws-opcode-pong+)
               ;; Ignore pong, continue
               (setf buffer remaining))

              ((= opcode +ws-opcode-close+)
               ;; Connection closing
               (ws-set conn :state :closed)
               (return-from ws-receive nil))

              (t
               ;; Text or binary frame
               (return-from ws-receive (cons opcode payload))))))

        ;; Need more data
        (let ((data (ws-raw-receive conn :timeout timeout)))
          (unless data
            (return-from ws-receive nil))
          (setf buffer (concatenate 'vector buffer data))
          (ws-set conn :recv-buffer buffer))))))

(defun ws-receive-text (conn &key (timeout 30))
  "Receive a text message. Returns the message as a string or nil."
  (let ((result (ws-receive conn :timeout timeout)))
    (when result
      (let ((opcode (car result))
            (payload (cdr result)))
        (when (= opcode +ws-opcode-text+)
          (map 'string #'code-char payload))))))

(defun ws-close (conn)
  "Close the WebSocket connection."
  (when (eq (ws-get conn :state) :open)
    (ws-send-close conn))
  (ws-raw-close conn))

;;; Test function
(defun ws-test (&optional (host "echo.websocket.org") (path "/"))
  "Test WebSocket connection to an echo server."
  (format t "~&WebSocket Test to ~a~%" host)
  (let ((conn (ws-connect host :path path)))
    (if conn
        (progn
          (format t "Connected! Sending test message...~%")
          (ws-send-text conn "Hello from Modus!")

          ;; Receive response
          (format t "Waiting for echo...~%")
          (let ((response (ws-receive-text conn :timeout 10)))
            (if response
                (progn
                  (format t "Got: ~a~%" response)
                  (if (string= response "Hello from Modus!")
                      (format t "Echo verified!~%")
                      (format t "Warning: response differs from sent message~%")))
                (format t "No response or timeout~%")))

          (ws-close conn)
          (format t "~%WebSocket test complete.~%"))
        (format t "Connection failed.~%"))))

