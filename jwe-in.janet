(import janetls :prefix "")
(import ./key :prefix "")
# (def k (pk/generate))

# (defn bb [b] (base64/encode (bignum/to-bytes b)))

# (def ex (pk/export-private k))

# (print "{\"alg\":\"RS256\", \"kty\":\"RSA\", \"n\": \""
#   (bb (ex :n)) "\", \"e\":\""
#   (bb (ex :e)) "\", \"d\":\""
#   (bb (ex :d)) "\", \"p\":\""
#   (bb (ex :p)) "\", \"q\":\""
#   (bb (ex :q)) "\", \"dp\":\""
#   (bb (ex :dp)) "\", \"dq\":\""
#   (bb (ex :dq)) "\", \"qi\":\""
#   (bb (ex :qp)) "\""
#   "}"
#   )



(def jwe {
  "ciphertext" "9iIOUBY3lWQruUyRtAB2gH0Jj9dwsLOWYrRDdVwqD9A"
  "encrypted_key" "vRX8dF7BUoWgUjePEK0jDgw-8t5_u_-RkiJQeJGngwxPX_KHj-2TNZYxOwBz6E35uAuRCxdRwnMCvoNqYF5QMR2oM3oSmw6rYuUQ447yKoAoIPbrQVIlUEoNxo6GMLhSx17g447PlruV9jtHo1P6umE8NNqm4w-5U2UtzDu2t1qi09Xcd7PPKwiHbCAn2upEzOa4aCVMVo3ks3yO_3oZKLBL3jDig-1c6swAdymQT4VJBxQ4w5XOQJWX5A4nyqcjI-Naq7NB2te2ttvBWKUxCpGzet14mYk6bDPAUklQFKfRFj0bU2f09L1sDwC4SROcTAASANwOlLfHCdRtOiR8wQ"
  "iv" "UiCWhy8Q9yDQvD96PqAbyQ"
  "protected" "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiR2VSRC1JbG1EOWxlZGZ5SFpqYlFxQ1hXem1uRlBLQmFrRE9QSElSX0FuSSIsInR5cCI6IkpXRSJ9"
  "tag" "kqB4pvBy6bXdCV5qOweiED0Qmp89XxbwTJ8WXddjPns"
  })

#
(def encrypted-key (base64/decode (jwe "encrypted_key")))
(def ciphertext (base64/decode (jwe "ciphertext")))
(def iv (base64/decode (jwe "iv")))
(def tag (base64/decode (jwe "tag")))
(def ad (jwe "protected"))
(var al (bignum/to-bytes (* 8 (length ad))))
(pp [:al (hex/encode al) (length al)])
(def zeros (hex/decode "0000000000000000"))
(if (< (length al) 8) (set al (string
  (slice zeros 0 (- 8 (length al)))
  al
  )))

(print "ADDITIONAL DATA (AD)")
(pp ad)

(print "IV")
(pp (hex/encode iv))

(print "CIPHERTEXT")
(pp (hex/encode ciphertext))

(print "Additional length (64 bit)")
(pp (hex/encode al))

(def key (pk/decrypt k encrypted-key))

(def hmac-key (slice key 0 32))
(def enc-key (slice key 32))

(print "HMAC KEY || CONTENT ENCRYPTION KEY")
(pp (hex/encode key))
(print (hex/encode hmac-key) " || " (hex/encode enc-key))



(def hmac-content (string ad iv ciphertext al))

(print "Content hmac'd: AD || IV || CIPHERTEXT || AL")
(pp (hex/encode hmac-content))
(print
(hex/encode ad) " || "
(hex/encode iv) " || "
(hex/encode ciphertext) " || "
(hex/encode al)
)

(print "Tag")
# (pp (hex/encode tag))

# JOSE cuts the hmac digest in half
(def calculated-tag (slice (md/hmac :sha512 hmac-key hmac-content :raw) 0 32))

(print "Calculated Tag")
(pp (hex/encode calculated-tag))

(print "Tag matches?")
(pp (constant= tag calculated-tag))

(def plaintext (cipher/decrypt :aes-cbc enc-key iv nil ciphertext nil))

(print "PLAINTEXT")
(pp plaintext)
