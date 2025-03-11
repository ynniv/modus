;;;; Nostr client for Movitz
;;;; NIP-01 basic protocol implementation

(in-package :muerte)

;;; Utilities

(defun bytes-to-hex (bytes)
  "Convert byte array to lowercase hex string."
  (let ((hex-chars "0123456789abcdef")
        (result (make-array (* 2 (length bytes)) :element-type 'character)))
    (dotimes (i (length bytes))
      (let ((byte (aref bytes i)))
        (setf (aref result (* i 2)) (char hex-chars (ash byte -4)))
        (setf (aref result (1+ (* i 2))) (char hex-chars (logand byte #xf)))))
    (coerce result 'string)))

(defun hex-to-bytes (hex)
  "Convert hex string to byte array."
  (let* ((len (floor (length hex) 2))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len)
      (setf (aref result i)
            (+ (* 16 (digit-char-p (char hex (* i 2)) 16))
               (digit-char-p (char hex (1+ (* i 2))) 16))))
    result))

(defun unix-timestamp ()
  "Get current Unix timestamp. Returns seconds since epoch.
   Note: Movitz doesn't have real time, so this returns a recent timestamp."
  ;; In real Movitz, we'd use PIT or RTC. For now, use a recent placeholder.
  ;; TODO: Get actual time from NTP or RTC
  1770443000)  ; Updated for testing - add buffer for boot/crypto time

;;; Event creation and signing

(defun nostr-serialize-for-id (pubkey-hex created-at kind tags content)
  "Serialize event data for ID computation (NIP-01).
   Returns JSON: [0, pubkey, created_at, kind, tags, content]"
  (json-serialize (list 0 pubkey-hex created-at kind tags content)))

(defun nostr-compute-id (pubkey-hex created-at kind tags content)
  "Compute event ID as SHA256 of serialized event."
  (let* ((serialized (nostr-serialize-for-id pubkey-hex created-at kind tags content))
         (bytes (make-array (length serialized) :element-type '(unsigned-byte 8))))
    (dotimes (i (length serialized))
      (setf (aref bytes i) (char-code (char serialized i))))
    (sha256 bytes)))

(defun nostr-sign-event (privkey event-id-bytes)
  "Sign event ID with Schnorr signature."
  (schnorr-sign privkey event-id-bytes))

(defun nostr-create-event (privkey kind content &key (tags nil))
  "Create a signed Nostr event.
   Returns alist suitable for JSON serialization."
  (let* ((tags (or tags #()))  ; Ensure empty vector for [] serialization
         (pubkey-bytes (schnorr-pubkey privkey))
         (pubkey-hex (bytes-to-hex pubkey-bytes))
         (created-at (unix-timestamp))
         (event-id-bytes (nostr-compute-id pubkey-hex created-at kind tags content))
         (event-id-hex (bytes-to-hex event-id-bytes))
         (sig-bytes (nostr-sign-event privkey event-id-bytes))
         (sig-hex (bytes-to-hex sig-bytes)))
    (list (cons "id" event-id-hex)
          (cons "pubkey" pubkey-hex)
          (cons "created_at" created-at)
          (cons "kind" kind)
          (cons "tags" tags)  ; Already guaranteed to be vector, not nil
          (cons "content" content)
          (cons "sig" sig-hex))))

;;; Publishing

(defun nostr-publish (conn event)
  "Publish an event to a relay."
  (let ((msg (json-serialize (list "EVENT" event))))
    (format t "Nostr: Publishing event ~a...~%"
            (subseq (json-get event "id") 0 8))
    (ws-send-text conn msg)))

(defun nostr-post (conn privkey content &key (kind 1) (tags nil))
  "Create and publish a text note (kind 1 by default)."
  (let ((event (nostr-create-event privkey kind content :tags tags)))
    (nostr-publish conn event)
    event))

;;; Nostr relay connection

(defun parse-relay-url (url)
  "Parse relay URL into (host port secure path).
   Supports: host, host:port, ws://host, wss://host:port/path"
  (let ((host url)
        (port nil)
        (secure nil)
        (path "/"))
    ;; Check for ws:// or wss:// prefix
    (cond
      ((and (> (length url) 6) (string= "wss://" (subseq url 0 6)))
       (setf host (subseq url 6))
       (setf secure t)
       (setf port 443))
      ((and (> (length url) 5) (string= "ws://" (subseq url 0 5)))
       (setf host (subseq url 5))
       (setf secure nil)
       (setf port 80)))
    ;; Extract path if present
    (let ((slash-pos (position #\/ host)))
      (when slash-pos
        (setf path (subseq host slash-pos))
        (setf host (subseq host 0 slash-pos))))
    ;; Extract port if present
    (let ((colon-pos (position #\: host)))
      (when colon-pos
        (setf port (parse-integer (subseq host (1+ colon-pos))))
        (setf host (subseq host 0 colon-pos))))
    ;; Default port based on security
    (unless port
      (setf port (if secure 443 80)))
    (list host port secure path)))

(defun nostr-connect (relay-url)
  "Connect to a Nostr relay.
   URL can be: host, host:port, ws://host:port, wss://host:port"
  (format t "~&Nostr: Connecting to ~a~%" relay-url)
  (let* ((parsed (parse-relay-url relay-url))
         (host (first parsed))
         (port (second parsed))
         (secure (third parsed))
         (path (fourth parsed)))
    (format t "Nostr: host=~a port=~d secure=~a path=~a~%" host port secure path)
    (let ((ws (ws-connect host :port port :path path :secure secure)))
      (when ws
        (format t "Nostr: Connected!~%"))
      ws)))

(defun nostr-close (conn)
  "Close Nostr connection."
  (ws-close conn))

;;; Subscribe
(defun nostr-subscribe (conn sub-id &key kinds limit authors p-tags)
  "Subscribe to events.
   kinds: list of event kinds
   limit: max number of events
   authors: list of pubkeys to filter by author
   p-tags: list of pubkeys to filter by #p tag"
  ;; Build filter as alist with dotted pairs (key . value)
  ;; Values that are lists need to be vectors for proper JSON serialization
  (let ((filter nil))
    (when kinds
      (push (cons "kinds" (coerce kinds 'vector)) filter))
    (when limit
      (push (cons "limit" limit) filter))
    (when authors
      (push (cons "authors" (coerce authors 'vector)) filter))
    (when p-tags
      (push (cons "#p" (coerce p-tags 'vector)) filter))
    (let ((msg (json-serialize (list "REQ" sub-id filter))))
      (format t "Nostr: Subscribe ~a~%" sub-id)
      (ws-send-text conn msg))))

;;; Parse message
(defun nostr-parse-message (msg)
  "Parse a Nostr message."
  (let ((parsed (json-parse msg)))
    (when (and (consp parsed) (stringp (car parsed)))
      (let ((msg-type (car parsed)))
        (cond
          ((string= msg-type "EVENT")
           (cons :event (cdr parsed)))
          ((string= msg-type "OK")
           ;; ["OK", event_id, success, message]
           (cons :ok (cdr parsed)))
          ((string= msg-type "EOSE")
           (cons :eose (second parsed)))
          ((string= msg-type "NOTICE")
           (cons :notice (second parsed)))
          ((string= msg-type "CLOSED")
           ;; ["CLOSED", subscription_id, message]
           (cons :closed (cdr parsed)))
          (t
           (cons :unknown parsed)))))))

;;; Receive
(defun nostr-receive (conn &key (timeout 30))
  "Receive a Nostr message."
  (let ((msg (ws-receive-text conn :timeout timeout)))
    (when msg
      (nostr-parse-message msg))))

;;; Display event
(defun nostr-display-event (event)
  "Display a Nostr event."
  (let ((pubkey (json-get event "pubkey"))
        (content (json-get event "content")))
    (format t "~&---~%")
    (when pubkey
      (format t "From: ~a...~%" (subseq pubkey 0 (min 8 (length pubkey)))))
    (when content
      (format t "~a~%" (subseq content 0 (min 200 (length content)))))
    (format t "---~%")))

;;; Test functions

(defun nostr-test (&optional (relay "nos.lol"))
  "Test Nostr connection (read-only)."
  (format t "~&=== Nostr Read Test ===~%")
  (let ((conn (nostr-connect relay)))
    (when conn
      (nostr-subscribe conn "test" :kinds (list 1) :limit 3)
      (format t "Waiting for events...~%")
      (dotimes (i 5)
        (let ((msg (nostr-receive conn :timeout 5)))
          (when msg
            (format t "Got: ~a~%" (car msg))
            (when (eq (car msg) :event)
              (nostr-display-event (second (cdr msg))))
            (when (eq (car msg) :eose)
              (return)))))
      (nostr-close conn)))
  (format t "~&=== Nostr Read Test Complete ===~%"))

(defun nostr-post-test (&optional (relay "127.0.0.1:7777"))
  "Test Nostr posting to a local relay."
  (format t "~&=== Nostr Post Test ===~%")
  (format t "Connecting to ~a...~%" relay)
  (let ((conn (nostr-connect relay)))
    (unless conn
      (format t "Failed to connect!~%")
      (return-from nostr-post-test nil))
    (format t "Connected!~%")
    ;; Use a test private key (DO NOT use in production!)
    (let* ((test-privkey #x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
           (pubkey-hex (bytes-to-hex (schnorr-pubkey test-privkey))))
      (format t "Pubkey: ~a~%" pubkey-hex)
      (format t "Creating event...~%")
      (let ((event (nostr-post conn test-privkey "Hello from Modus! A bare-metal Lisp OS.")))
        (format t "Event ID: ~a~%" (json-get event "id"))
        ;; Wait for OK response
        (format t "Waiting for relay response...~%")
        (let ((response (nostr-receive conn :timeout 10)))
          (if response
              (format t "Response: ~a~%" response)
              (format t "No response (timeout)~%"))))
      (nostr-close conn)))
  (format t "~&=== Nostr Post Test Complete ===~%"))

(defun nostr-demo (&optional (relay "127.0.0.1:7777"))
  "Demo: post a note and read it back."
  (format t "~&=== Nostr Demo ===~%")
  (let ((conn (nostr-connect relay))
        (test-privkey #x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef))
    (unless conn
      (format t "Failed to connect to ~a~%" relay)
      (return-from nostr-demo nil))
    ;; Post
    (let* ((pubkey-hex (bytes-to-hex (schnorr-pubkey test-privkey)))
           (event (nostr-post conn test-privkey "Modus says hello!")))
      (format t "Posted! ID: ~a...~%" (subseq (json-get event "id") 0 16))
      ;; Wait for OK
      (nostr-receive conn :timeout 5)
      ;; Subscribe to our own posts
      (format t "Reading back...~%")
      (nostr-subscribe conn "self" :kinds (list 1) :limit 1)
      (dotimes (i 3)
        (let ((msg (nostr-receive conn :timeout 5)))
          (when (and msg (eq (car msg) :event))
            (nostr-display-event (second (cdr msg)))
            (return)))))
    (nostr-close conn))
  (format t "~&=== Nostr Demo Complete ===~%"))

(provide :lib/net/nostr)
