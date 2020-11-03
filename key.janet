(import janetls :prefix "")
(def jwk {
  "alg" "RS256"
  "kty" "RSA"
  "n" "vfqF7S/dgxm/K7C7r7gc27a/pUPv8jZgjuchDB/fQthDZ19sM1qt76rrTQg8Ey61bRQnzYXN2m7T/KybRe+JV+TdbmtprdQgYNv7U09S1ISckkZ/v8VMu6FX9j82EVkgTUoZuyB3WoZuMz2UEynioHqD26xLFYZoDWOFrOgJ50uKbLDHNK8nKB2g8sTGVkABuX0apYY/OpOJSgx4ZQcRGUMYee3xn1QiszYyvMSijTzKm3iFr6G4IodK/fwBlf3zsyWbMTi8kl7r1CY/fHPoXf7C7UcUIQ69YMzsUdf5m82Ie5HJgU/GP+KOY/rA6EzLSyuwCZuCCes/ycqV2e1Unw==" 
  "e" "AQAB"
  "d" "G0izBPJLtwvdZkTEDRj9NVraIZM6ZIgFtxBKW+eUlLuNdqJViPc8JWsKecOLKTAbSJainsQu4RuV9g3DYQ26pQpj+NCUBViClpaRUjuBXa8hSMAM5yRKqw8hcbv4o7uFRZm091MoK7KZz2HHyzbH6vHyz6Y/bvsgz3zHEng4D+UMThY6HK0M3h2ken1oRth5HoDvLmTtOpIps3ZpjItP5C4uBGRg/kqyW3Tly0lbPz57uuf0jT8bIXfnPK/mbK3gfv0mqeg7NQN6byEKDkkt2gC3fL87CzZZh1L+nJiveXyvgxmbbONHr3BoS6XOuH2TDkTGC1Z1w7kvfQbHLRDTzQ==" 
  "p" "80/1E2B8aVb3mXrLAVUMZExzqw39IEgma5ooIssbRzyMtNDfon20OmCQmmmntKxLsAzBv3nbxWGLAAOZ7Vafrlw4Tra/siG0ZDFJk9/c+Mn0B5/Mf+hKTngqMU47sDCWpA0r4XF5R/7SW1qnWoNeujVI6duRRV3AKN7ru+tIkyU="
  "q" "x+KZb4IP93E49icqntemCppKLFV4o7tVWbKpwuj4HIGLZ7z9rh02mBYtSakdvV8QzNb9Za4v8OEwIgAkGVYKEnRFPx9IUezzYiKXzpN1PxEEyyNNFL4KPK5szAZFviD9LShfFVttSmXsm5r7WOnlpJWjjjcXsW/K9Dlfaimu33M="
  "dp" "EH+vgqzcQthe2c11zpVRzctRXJwKOhIqaMl/Rzy2kNIOSISRZZdYjUzXAWGAucOlLj7vNGiy+mNu5YVY/rsNAOnH9650uUOH0/Nzpc9cUJKBNbMkTtgVkdScJ9PCQGRLErzB6Puk2bjx0rgG+SBHYCEU3KbC5w1AZoUXPxrpRPE=" 
  "dq" "TdgW71FUzIYArASW2aOcW5a4+kkTIZjMZZFqAalfLyLYWr9EgHGKGHLSklRVa7HBRjUYHGhY7VOVvjgV1vQmGgfEDBAvxxAjvP1B58aPq88B8ea+lyxnqjg30MFEmgYY82Q8m4Gur4HAQt15s6frskxAlRsplAW4oaJSYXL4Urc="
  "qi" "K1sZbejgybDcKUjRnFUvwBCgno9U03UJi1lOl0FS4HjUoADTuykCRcvU+LJQkW48qy26H5O5axZKL2wYP/HLWKEm2z/92Mvbt01FujrGwfnwEnoekPxo+Ykul7Xlcz0LYOhNvs702om3CAYEaYc7Q4SqFtw2JMbzntMx8B398tY="
  })

(def k (pk/import {
  :type :rsa 
  :version :pkcs1-v2.1
  :n (bignum/parse-bytes (base64/decode (jwk "n")))
  :e (bignum/parse-bytes (base64/decode (jwk "e")))
  :d (bignum/parse-bytes (base64/decode (jwk "d")))
  :p (bignum/parse-bytes (base64/decode (jwk "p")))
  :q (bignum/parse-bytes (base64/decode (jwk "q")))
  }))
