(import janetls :prefix "")
(import ./key :prefix "")
(def protected `{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","kid":"GeRD-IlmD9ledfyHZjbQqCXWzmnFPKBakDOPHIR_AnI","typ":"JWE"}`)
(def iv (util/random 16))
(def enc-key (util/random 32))
(def hmac-key (util/random 32))
(def plaintext "Hello From Janet")
(def [iv ciphertext] (cipher/encrypt :aes-cbc enc-key nil nil plaintext))

(def ad (base64/encode protected))
(var al (bignum/to-bytes (* 8 (length ad))))
(pp [:al (hex/encode al) (length al)])
(def zeros (hex/decode "0000000000000000"))
(if (< (length al) 8) (set al (string
  (slice zeros 0 (- 8 (length al)))
  al
  )))

(def hmac-content (string ad iv ciphertext al))
(print
(hex/encode ad) " || "
(hex/encode iv) " || "
(hex/encode ciphertext) " || "
(hex/encode al)
)
(def tag (slice (md/hmac :sha512 hmac-key hmac-content :raw) 0 32))
(def key (string hmac-key enc-key))
(def encrypted-key (pk/encrypt k key))
(print 
  `{"ciphertext":"`
  (base64/encode ciphertext :url-unpadded)
  `","encrypted_key":"`
  (base64/encode encrypted-key :url-unpadded)
  `","iv":"`
  (base64/encode iv :url-unpadded)
  `","protected":"`
  (base64/encode protected :url-unpadded)
  `","tag":"`
  (base64/encode tag :url-unpadded)
  `"}`
  )