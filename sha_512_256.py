initial_sha_512_hash_values = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
           0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e217]

initial_sha_512_256_hash_values = []

for i in range(8):
    initial_sha_512_256_hash_values.append(initial_sha_512_hash_values[i] ^ 0xa5a5a5a5a5a5a5a5)
# Ši funkcija sugeneruoja prandines hash reikšmes SHA-512/256 šifravimo algortimui.
def sha_512_256_iv_generation():
    pass

print(initial_sha_512_256_hash_values[0])