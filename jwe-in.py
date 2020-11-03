from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode
public_key = jwk.JWK()
private_key = """
{"alg":"RS256", "kty":"RSA", "n": "vfqF7S/dgxm/K7C7r7gc27a/pUPv8jZgjuchDB/fQthDZ19sM1qt76rrTQg8Ey61bRQnzYXN2m7T/KybRe+JV+TdbmtprdQgYNv7U09S1ISckkZ/v8VMu6FX9j82EVkgTUoZuyB3WoZuMz2UEynioHqD26xLFYZoDWOFrOgJ50uKbLDHNK8nKB2g8sTGVkABuX0apYY/OpOJSgx4ZQcRGUMYee3xn1QiszYyvMSijTzKm3iFr6G4IodK/fwBlf3zsyWbMTi8kl7r1CY/fHPoXf7C7UcUIQ69YMzsUdf5m82Ie5HJgU/GP+KOY/rA6EzLSyuwCZuCCes/ycqV2e1Unw==", "e":"AQAB", "d":"G0izBPJLtwvdZkTEDRj9NVraIZM6ZIgFtxBKW+eUlLuNdqJViPc8JWsKecOLKTAbSJainsQu4RuV9g3DYQ26pQpj+NCUBViClpaRUjuBXa8hSMAM5yRKqw8hcbv4o7uFRZm091MoK7KZz2HHyzbH6vHyz6Y/bvsgz3zHEng4D+UMThY6HK0M3h2ken1oRth5HoDvLmTtOpIps3ZpjItP5C4uBGRg/kqyW3Tly0lbPz57uuf0jT8bIXfnPK/mbK3gfv0mqeg7NQN6byEKDkkt2gC3fL87CzZZh1L+nJiveXyvgxmbbONHr3BoS6XOuH2TDkTGC1Z1w7kvfQbHLRDTzQ==", "p":"80/1E2B8aVb3mXrLAVUMZExzqw39IEgma5ooIssbRzyMtNDfon20OmCQmmmntKxLsAzBv3nbxWGLAAOZ7Vafrlw4Tra/siG0ZDFJk9/c+Mn0B5/Mf+hKTngqMU47sDCWpA0r4XF5R/7SW1qnWoNeujVI6duRRV3AKN7ru+tIkyU=", "q":"x+KZb4IP93E49icqntemCppKLFV4o7tVWbKpwuj4HIGLZ7z9rh02mBYtSakdvV8QzNb9Za4v8OEwIgAkGVYKEnRFPx9IUezzYiKXzpN1PxEEyyNNFL4KPK5szAZFviD9LShfFVttSmXsm5r7WOnlpJWjjjcXsW/K9Dlfaimu33M=", "dp":"EH+vgqzcQthe2c11zpVRzctRXJwKOhIqaMl/Rzy2kNIOSISRZZdYjUzXAWGAucOlLj7vNGiy+mNu5YVY/rsNAOnH9650uUOH0/Nzpc9cUJKBNbMkTtgVkdScJ9PCQGRLErzB6Puk2bjx0rgG+SBHYCEU3KbC5w1AZoUXPxrpRPE=", "dq":"TdgW71FUzIYArASW2aOcW5a4+kkTIZjMZZFqAalfLyLYWr9EgHGKGHLSklRVa7HBRjUYHGhY7VOVvjgV1vQmGgfEDBAvxxAjvP1B58aPq88B8ea+lyxnqjg30MFEmgYY82Q8m4Gur4HAQt15s6frskxAlRsplAW4oaJSYXL4Urc=", "qi":"K1sZbejgybDcKUjRnFUvwBCgno9U03UJi1lOl0FS4HjUoADTuykCRcvU+LJQkW48qy26H5O5axZKL2wYP/HLWKEm2z/92Mvbt01FujrGwfnwEnoekPxo+Ykul7Xlcz0LYOhNvs702om3CAYEaYc7Q4SqFtw2JMbzntMx8B398tY="}
"""
jwe_in = """
{"ciphertext":"ijQpVpdgIsGoel3qqsLvh-9grs0Nbz86Bn9MtTPwol8","encrypted_key":"TFQbkYGffHOn-Oks27HBZE4BQqRet2nZLaUoQSm044PhGoqaYwKI4rWHMbJx0ox-HE2IKDJ4uLG243A6t_La_1_N4TaJlI2PvmQpr3N3rMZCwZ0EU2tpUFNxOJwuwxhQmNw7vfv7LAZU36v_wyps8y_zrj2sItMBN3254eMN_3LqyvZaDBfR5D8DYeoC7jOHUOwhYFzMlZyeowT_LbNbow3hJ7BZe93VJn31Ec90vdAa3fzvNuxbJvgHH5k3mjuMOFveZE5F1gYyBvQE70exisJXxksPcOV0IOtDJIlFKAKLItKhapJ1cUchVXfE4MXprJBzVnM3OiT-SbkGnuu5hQ","iv":"4RjdUS1QItA2x_eGY4gCZg","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiR2VSRC1JbG1EOWxlZGZ5SFpqYlFxQ1hXem1uRlBLQmFrRE9QSElSX0FuSSIsInR5cCI6IkpXRSJ9","tag":"y5WgBQZB9vu1bES5-qa-HHmXOHEsaRgBXR24xgUWRHo"}
"""
# jwe_in = """
# {"ciphertext":"P8_CaYSHyhm-rSl9qKIBgPzcdwMOFgb5k2euzgD-UtI","encrypted_key":"iXoXKRY8hJKOGN-hOsY24tX7bPhoJvVQGfpa9O-wL7If5TimberukjS4-1UaBJuA61Vj_9ZciJnI03SYC4XHB8NOLMcgUvTRTVSZeDr-mefRZI9JyyqJcWp_eXNxwaSLOXEe1HiKerM2GiLX4HDz0ixVsOUdMdjFJFRQJQwt6KThhi7Rtgf9rSBK0wEvgC8Hh49T3FTFigV1tmt86d7w9-OFuEE7YhyqDfzvt6Y4pnPQf7VjniP09x3RBEAQz1JUhFem630jZmytQl7TbUgvxv-VBf211h40GLWr1wPkx5ba6saeZKW8k-lBBn2jJ1T77H7bTiyxnmBYwD9MfRflnQ","iv":"KFw9-8IznlosK7ylS73imw","protected":"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiR2VSRC1JbG1EOWxlZGZ5SFpqYlFxQ1hXem1uRlBLQmFrRE9QSElSX0FuSSIsInR5cCI6IkpXRSJ9","tag":"isTifis5glQ5fz-kA7kXi5mde0SqCyERByR0lTS6EAY"}
# """
public_key.import_key(**json_decode(private_key))
print(public_key.has_private)
payload = "My Encrypted message"
protected_header = {
    "alg": "RSA-OAEP-256",
    "enc": "A256CBC-HS512",
    "typ": "JWE",
    "kid": public_key.thumbprint(),
}
jwetoken = jwe.JWE()
print(jwetoken.deserialize(jwe_in, key=public_key))
print(jwetoken.payload)
