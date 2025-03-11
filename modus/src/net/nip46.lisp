;;;; NIP-46: Nostr Connect (nsecBunker client)
;;;; https://github.com/nostr-protocol/nips/blob/master/46.md

(require :lib/crypto/nip44)
(require :lib/crypto/secp256k1)
(require :lib/net/nostr)
(require :lib/json)

(provide :lib/net/nip46)

(in-package :muerte)

;;; NIP-46 uses encrypted messages over Nostr relays
;;; Client generates ephemeral keypair, bunker has the real keys
;;; Communication via kind 24133 events

(defconstant +nip46-kind+ 24133)

;;; Bunker connection state
(defun make-bunker-connection (bunker-pubkey relay-url &key secret)
  "Create a bunker connection state."
  ;; Generate ephemeral client keypair
  (let* ((client-privkey (random-privkey))
         (client-pubkey-bytes (schnorr-pubkey client-privkey))
         (client-pubkey-hex (bytes-to-hex client-pubkey-bytes)))
    (list :bunker-pubkey bunker-pubkey
          :relay-url relay-url
          :secret secret
          :client-privkey client-privkey
          :client-pubkey client-pubkey-hex
          :conn nil
          :request-id 0)))

(defun random-privkey ()
  "Generate a random 256-bit private key."
  ;; In production, use a proper CSPRNG
  (let ((key 0))
    (dotimes (i 32)
      (setf key (logior (ash key 8) (random 256))))
    key))

(defun bunker-get (bunker key)
  (getf bunker key))

(defun bunker-set (bunker key value)
  (setf (getf bunker key) value))

;;; Parse bunker:// connection string
(defun parse-bunker-url (url)
  "Parse bunker://pubkey?relay=url&secret=xxx into (pubkey relay secret)."
  (unless (and (> (length url) 9) (string= "bunker://" (subseq url 0 9)))
    (error "Invalid bunker URL: ~a" url))
  (let* ((rest (subseq url 9))
         (query-pos (position #\? rest))
         (pubkey (if query-pos (subseq rest 0 query-pos) rest))
         (relay nil)
         (secret nil))
    ;; Parse query params
    (when query-pos
      (let ((query (subseq rest (1+ query-pos))))
        (loop for param in (split-string query #\&) do
          (let ((eq-pos (position #\= param)))
            (when eq-pos
              (let ((key (subseq param 0 eq-pos))
                    (val (subseq param (1+ eq-pos))))
                (cond
                  ((string= key "relay") (setf relay (url-decode val)))
                  ((string= key "secret") (setf secret (url-decode val))))))))))
    (list pubkey relay secret)))

(defun split-string (str delimiter)
  "Split string by delimiter character."
  (let ((result nil)
        (start 0))
    (loop for i from 0 below (length str)
          when (char= (char str i) delimiter)
          do (progn
               (push (subseq str start i) result)
               (setf start (1+ i))))
    (push (subseq str start) result)
    (nreverse result)))

(defun url-decode (str)
  "Decode URL-encoded string (%XX -> char)."
  (let ((result (make-array (length str) :element-type 'character :fill-pointer 0 :adjustable t))
        (i 0)
        (len (length str)))
    (loop while (< i len) do
      (let ((c (char str i)))
        (cond
          ((and (char= c #\%) (< (+ i 2) len))
           ;; Decode %XX
           (let* ((h1 (digit-char-p (char str (+ i 1)) 16))
                  (h2 (digit-char-p (char str (+ i 2)) 16)))
             (when (and h1 h2)
               (vector-push-extend (code-char (+ (* h1 16) h2)) result)
               (incf i 3))))
          ((char= c #\+)
           ;; + means space in URL encoding
           (vector-push-extend #\space result)
           (incf i))
          (t
           (vector-push-extend c result)
           (incf i)))))
    (coerce result 'string)))

;;; Connect to bunker
(defun bunker-connect (bunker-url)
  "Connect to an nsecBunker.
   bunker-url: bunker://pubkey?relay=wss://...&secret=xxx
   Returns: bunker connection object."
  (format t "~&Bunker: Parsing URL...~%")
  (let* ((parsed (parse-bunker-url bunker-url))
         (pubkey (first parsed))
         (relay (second parsed))
         (secret (third parsed)))
    (format t "Bunker pubkey: ~a...~%" (subseq pubkey 0 16))
    (format t "Relay: ~a~%" relay)
    (let ((bunker (make-bunker-connection pubkey relay :secret secret)))
      ;; Connect to relay
      (format t "Bunker: Connecting to relay...~%")
      (let ((conn (nostr-connect relay)))
        (unless conn
          (error "Failed to connect to relay"))
        (bunker-set bunker :conn conn)
        ;; Subscribe to responses for our ephemeral pubkey
        (let ((client-pubkey (bunker-get bunker :client-pubkey)))
          (format t "Bunker: Client pubkey: ~a...~%" (subseq client-pubkey 0 16))
          (nostr-subscribe conn "bunker"
                           :kinds (list +nip46-kind+)
                           :p-tags (list client-pubkey)))
        bunker))))

;;; Send request to bunker
(defun bunker-request (bunker method &rest params)
  "Send a request to the bunker and wait for response.
   method: string like 'sign_event', 'get_public_key', etc.
   params: list of parameters
   Returns: result from bunker or signals error."
  (let* ((conn (bunker-get bunker :conn))
         (bunker-pubkey (bunker-get bunker :bunker-pubkey))
         (client-privkey (bunker-get bunker :client-privkey))
         (client-pubkey (bunker-get bunker :client-pubkey))
         ;; Generate request ID
         (req-id (format nil "~d" (incf (getf bunker :request-id))))
         ;; Build JSON-RPC request
         (request (list (cons "id" req-id)
                        (cons "method" method)
                        (cons "params" (or params #()))))
         (request-json (json-serialize request)))
    (format t "Bunker: Request ~a: ~a~%" req-id method)
    ;; Encrypt request with NIP-44
    (let ((encrypted (nip44-encrypt client-privkey bunker-pubkey request-json)))
      ;; Create kind 24133 event
      (let* ((created-at (unix-timestamp))
             (tags (list (list "p" bunker-pubkey)))
             ;; Debug: show full serialization for ID
             (id-serialized (nostr-serialize-for-id client-pubkey created-at +nip46-kind+ tags encrypted))
             (_ (format t "Bunker: ID serialization (~a chars):~%" (length id-serialized)))
             (_ (format t "  Start: ~a~%" (subseq id-serialized 0 (min 120 (length id-serialized)))))
             (_ (format t "  Tags part: ~a~%" (json-serialize tags)))
             (event-id-bytes (nostr-compute-id client-pubkey created-at +nip46-kind+ tags encrypted))
             (event-id-hex (bytes-to-hex event-id-bytes))
             (sig-bytes (schnorr-sign client-privkey event-id-bytes))
             (sig-hex (bytes-to-hex sig-bytes))
             (event (list (cons "id" event-id-hex)
                          (cons "pubkey" client-pubkey)
                          (cons "created_at" created-at)
                          (cons "kind" +nip46-kind+)
                          (cons "tags" tags)
                          (cons "content" encrypted)
                          (cons "sig" sig-hex))))
        ;; Debug: print event details
        (format t "Bunker: Event tags: ~a~%" (json-serialize tags))
        (format t "Bunker: Event ID: ~a~%" event-id-hex)
        (format t "Bunker: Pubkey: ~a~%" client-pubkey)
        (let ((event-json (json-serialize event)))
          (format t "Bunker: Full event JSON (~a chars)~%" (length event-json)))
        ;; Send event
        (nostr-publish conn event)
        ;; Check relay OK response
        (format t "Bunker: Checking relay response...~%")
        (let ((relay-response (nostr-receive conn :timeout 5)))
          (format t "Bunker: Relay response: ~a~%" relay-response)
          (when (and relay-response (eq (car relay-response) :ok))
            (let ((ok-success (second (cdr relay-response)))
                  (ok-message (third (cdr relay-response))))
              (format t "Bunker: OK success=~a message=~a~%" ok-success ok-message)
              (unless ok-success
                (error "Relay rejected event: ~a" ok-message)))))
        ;; Wait for response from bunker
        (format t "Bunker: Waiting for bunker response...~%")
        (bunker-wait-response bunker req-id)))))

(defun bunker-wait-response (bunker req-id &optional (timeout 60))
  "Wait for response from bunker with matching request ID."
  (let ((conn (bunker-get bunker :conn))
        (bunker-pubkey (bunker-get bunker :bunker-pubkey))
        (client-privkey (bunker-get bunker :client-privkey)))
    (dotimes (attempt timeout)
      (let ((msg (nostr-receive conn :timeout 1)))
        (when (and msg (eq (car msg) :event))
          (let* ((event (second (cdr msg)))
                 (from-pubkey (json-get event "pubkey"))
                 (content (json-get event "content")))
            ;; Check it's from the bunker
            (when (string= from-pubkey bunker-pubkey)
              ;; Decrypt response with NIP-44
              (let* ((decrypted (nip44-decrypt client-privkey bunker-pubkey content))
                     (response (json-parse decrypted))
                     (response-id (json-get response "id")))
                ;; Check request ID matches
                (when (string= response-id req-id)
                  (let ((result (json-get response "result"))
                        (error-msg (json-get response "error")))
                    (when error-msg
                      (error "Bunker error: ~a" error-msg))
                    (format t "Bunker: Got response~%")
                    (return-from bunker-wait-response result)))))))))
    (error "Bunker response timeout")))

;;; High-level API

(defun bunker-get-public-key (bunker)
  "Get the public key from the bunker."
  (bunker-request bunker "get_public_key"))

(defun bunker-sign-event (bunker unsigned-event)
  "Sign an event using the bunker.
   unsigned-event: alist with id, pubkey, created_at, kind, tags, content
   Returns: signature hex string."
  (let ((event-json (json-serialize unsigned-event)))
    (bunker-request bunker "sign_event" event-json)))

(defun bunker-nip04-encrypt (bunker pubkey plaintext)
  "Encrypt a message using bunker's key (NIP-04)."
  (bunker-request bunker "nip04_encrypt" pubkey plaintext))

(defun bunker-nip04-decrypt (bunker pubkey ciphertext)
  "Decrypt a message using bunker's key (NIP-04)."
  (bunker-request bunker "nip04_decrypt" pubkey ciphertext))

;;; Convenience function for posting via bunker
(defun bunker-post (bunker content &key (kind 1) (tags nil))
  "Post a message to Nostr using the bunker for signing."
  (let* ((conn (bunker-get bunker :conn))
         ;; Get pubkey from bunker
         (pubkey (bunker-get-public-key bunker))
         (created-at (unix-timestamp))
         (tags (or tags #()))
         ;; Compute event ID
         (event-id-bytes (nostr-compute-id pubkey created-at kind tags content))
         (event-id-hex (bytes-to-hex event-id-bytes))
         ;; Create unsigned event
         (unsigned-event (list (cons "id" event-id-hex)
                               (cons "pubkey" pubkey)
                               (cons "created_at" created-at)
                               (cons "kind" kind)
                               (cons "tags" tags)
                               (cons "content" content)))
         ;; Get signature from bunker
         (sig (bunker-sign-event bunker unsigned-event))
         ;; Complete event
         (event (append unsigned-event (list (cons "sig" sig)))))
    (format t "Bunker: Publishing event ~a...~%"
            (subseq event-id-hex 0 8))
    (nostr-publish conn event)
    event))

;;; Close connection
(defun bunker-close (bunker)
  "Close the bunker connection."
  (let ((conn (bunker-get bunker :conn)))
    (when conn
      (nostr-close conn))))

;;; Test functions
(defun bunker-test (bunker-url)
  "Test bunker connection."
  (format t "~&=== nsecBunker Test ===~%")
  (let ((bunker (bunker-connect bunker-url)))
    (format t "Getting public key...~%")
    (let ((pubkey (bunker-get-public-key bunker)))
      (format t "Bunker pubkey: ~a~%" pubkey))
    (bunker-close bunker))
  (format t "=== nsecBunker Test Complete ===~%"))

(defun bunker-quick-test (pubkey &optional (relay "wss://nos.lol"))
  "Quick test with just pubkey (relay defaults to nos.lol)."
  (let ((url (format nil "bunker://~a?relay=~a" pubkey relay)))
    (bunker-test url)))

;; Hardcoded test for serial line length limitations
(defparameter *test-bunker-pubkey*
  "d3318c197fba307bde5023da0547ff162d8126e17ccbb32beecc4f78d9a33dd6")

(defun bunker-demo ()
  "Demo bunker connection with hardcoded test pubkey."
  (bunker-quick-test *test-bunker-pubkey*))

(defun bunker-proxy-test ()
  "Test bunker via local proxy (avoids QEMU slirp issues with large TLS packets).
   Start relay-proxy.py on host first: python3 relay-proxy.py"
  (bunker-quick-test *test-bunker-pubkey* "ws://10.0.2.2:7777"))

(defun bunker-no-subscribe-test ()
  "Test NIP-46 event with pre-computed values to minimize delay after connect."
  (format t "~&=== Bunker No-Subscribe Test (Fast) ===~%")
  (let* ((relay "wss://nos.lol")
         (bunker-pubkey *test-bunker-pubkey*))
    ;; Pre-compute everything before connecting
    (format t "Pre-computing keypair...~%")
    (let* ((client-privkey (random-privkey))
           (client-pubkey-bytes (schnorr-pubkey client-privkey))
           (client-pubkey-hex (bytes-to-hex client-pubkey-bytes)))
      (format t "Pre-encrypting NIP-44...~%")
      (let* ((request-json "{\"id\":\"1\",\"method\":\"get_public_key\",\"params\":[]}")
             (encrypted (nip44-encrypt client-privkey bunker-pubkey request-json))
             (created-at (unix-timestamp))
             (tags (list (list "p" bunker-pubkey))))
        (format t "Pre-computing event ID and signature...~%")
        (let* ((event-id-bytes (nostr-compute-id client-pubkey-hex created-at +nip46-kind+ tags encrypted))
               (event-id-hex (bytes-to-hex event-id-bytes))
               (sig-bytes (schnorr-sign client-privkey event-id-bytes))
               (sig-hex (bytes-to-hex sig-bytes))
               (event (list (cons "id" event-id-hex)
                            (cons "pubkey" client-pubkey-hex)
                            (cons "created_at" created-at)
                            (cons "kind" +nip46-kind+)
                            (cons "tags" tags)
                            (cons "content" encrypted)
                            (cons "sig" sig-hex))))
          ;; GC already happened during crypto operations above
          (format t "Event ready. ID: ~a...~%" (subseq event-id-hex 0 16))
          (format t "Connecting to ~a...~%" relay)
          (let ((conn (nostr-connect relay)))
            (unless conn
              (format t "Failed to connect!~%")
              (return-from bunker-no-subscribe-test nil))
            (format t "Connected! Publishing IMMEDIATELY...~%")
            (nostr-publish conn event)
            (format t "Waiting for relay response...~%")
            (let ((response (nostr-receive conn :timeout 10)))
              (format t "Response: ~a~%" response))
            (nostr-close conn))))))
  (format t "=== Test Complete ===~%"))

(defun bunker-full-post-test (&optional (message "Hello from Modus via nsecBunker!"))
  "Full bunker test: connect, get signature, publish note."
  (format t "~&=== Bunker Full Post Test ===~%")
  (let* ((relay "wss://nos.lol")
         (bunker-pubkey *test-bunker-pubkey*))
    ;; Generate ephemeral client keypair
    (format t "Generating client keypair...~%")
    (let* ((client-privkey (random-privkey))
           (client-pubkey-bytes (schnorr-pubkey client-privkey))
           (client-pubkey-hex (bytes-to-hex client-pubkey-bytes)))
      (format t "Client pubkey: ~a...~%" (subseq client-pubkey-hex 0 16))

      ;; Connect to relay
      (format t "Connecting to ~a...~%" relay)
      (let ((conn (nostr-connect relay)))
        (unless conn
          (format t "Failed to connect!~%")
          (return-from bunker-full-post-test nil))
        (format t "Connected!~%")

        ;; Subscribe to responses for our client pubkey
        (format t "Subscribing for responses...~%")
        (nostr-subscribe conn "bunker-resp"
                         :kinds (list +nip46-kind+)
                         :p-tags (list client-pubkey-hex))

        ;; Wait for EOSE
        (nostr-receive conn :timeout 5)

        ;; Build the note we want to sign
        (let* ((created-at (unix-timestamp))
               (kind 1)
               (tags #())
               (event-id-bytes (nostr-compute-id bunker-pubkey created-at kind tags message))
               (event-id-hex (bytes-to-hex event-id-bytes))
               (unsigned-event (list (cons "id" event-id-hex)
                                     (cons "pubkey" bunker-pubkey)
                                     (cons "created_at" created-at)
                                     (cons "kind" kind)
                                     (cons "tags" tags)
                                     (cons "content" message))))
          (format t "Unsigned event ID: ~a...~%" (subseq event-id-hex 0 16))

          ;; Create sign_event request
          (let* ((unsigned-json (json-serialize unsigned-event))
                 (request (list (cons "id" "sign1")
                               (cons "method" "sign_event")
                               (cons "params" (list unsigned-json))))
                 (request-json (json-serialize request)))
            (format t "Request: ~a...~%" (subseq request-json 0 (min 60 (length request-json))))

            ;; Encrypt with NIP-44
            (format t "Encrypting request...~%")
            (let ((encrypted (nip44-encrypt client-privkey bunker-pubkey request-json)))

              ;; Create NIP-46 event
              (let* ((nip46-tags (list (list "p" bunker-pubkey)))
                     (nip46-id-bytes (nostr-compute-id client-pubkey-hex created-at +nip46-kind+ nip46-tags encrypted))
                     (nip46-id-hex (bytes-to-hex nip46-id-bytes))
                     (sig-bytes (schnorr-sign client-privkey nip46-id-bytes))
                     (sig-hex (bytes-to-hex sig-bytes))
                     (nip46-event (list (cons "id" nip46-id-hex)
                                        (cons "pubkey" client-pubkey-hex)
                                        (cons "created_at" created-at)
                                        (cons "kind" +nip46-kind+)
                                        (cons "tags" nip46-tags)
                                        (cons "content" encrypted)
                                        (cons "sig" sig-hex))))
                (format t "Publishing sign_event request...~%")
                (nostr-publish conn nip46-event)

                ;; Wait for relay OK
                (let ((ok-response (nostr-receive conn :timeout 10)))
                  (format t "Relay response: ~a~%" ok-response))

                ;; Wait for bunker response
                (format t "Waiting for bunker response...~%")
                (let ((bunker-response nil))
                  (dotimes (i 30)
                    (let ((msg (nostr-receive conn :timeout 2)))
                      (when msg
                        (format t "Got: ~a~%" (car msg))
                        (when (eq (car msg) :event)
                          (let* ((event (second (cdr msg)))
                                 (from-pubkey (json-get event "pubkey")))
                            (when (string= from-pubkey bunker-pubkey)
                              (format t "Got bunker response!~%")
                              (let* ((content (json-get event "content"))
                                     (decrypted (nip44-decrypt client-privkey bunker-pubkey content))
                                     (response (json-parse decrypted)))
                                (format t "Decrypted: ~a~%" decrypted)
                                (setf bunker-response response)
                                (return))))))))

                  (if bunker-response
                      ;; The result field is a JSON string containing the full signed event
                      (let* ((result-str (json-get bunker-response "result"))
                             (signed-event (json-parse result-str))
                             (sig (json-get signed-event "sig"))
                             (tags (json-get signed-event "tags")))
                        (format t "Got signature: ~a...~%" (subseq sig 0 32))
                        ;; Fix: nil tags should be empty vector for proper JSON []
                        (when (null tags)
                          (setf signed-event
                                (mapcar (lambda (pair)
                                          (if (string= (car pair) "tags")
                                              (cons "tags" #())
                                              pair))
                                        signed-event)))
                        (format t "Publishing signed note...~%")
                        (nostr-publish conn signed-event)
                        (let ((final-response (nostr-receive conn :timeout 10)))
                          (format t "Final response: ~a~%" final-response)
                          ;; Print note identifiers
                          (let ((event-id (json-get signed-event "id")))
                            (format t "~%=== Published Note ===~%")
                            (format t "Event ID: ~a~%" event-id)
                            (format t "Note ID (hex): note1...~a~%" (subseq event-id (- (length event-id) 8)))
                            (format t "~%View at: https://njump.me/~a~%" event-id))))
                      (format t "No response from bunker~%")))))))

        (nostr-close conn))))
  (format t "=== Bunker Full Post Test Complete ===~%"))
