# Pirminės maišos reikšmės SHA-512/256 algoritmui.
initial_sha_512_256_hash_values = [0x022312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151,
0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa,0x0eb72ddc81c52ca2]


with open('file.txt', 'rb') as file:
    input = bytearray(file.read())
    input_length = len(input) * 8
    input += ((1 << 7).to_bytes(1, byteorder='little'))
    input.extend(bytearray((896 - input_length - 8) // 8))
    input += (input_length).to_bytes(16, byteorder='big')
    for (i, char) in enumerate(input):
      if ((i + 1) % 4 == 0):
        print(format(char, '08b'))
      else:
        print(format(char, '08b'), end=' ')
