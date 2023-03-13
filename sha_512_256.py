# Pirminės maišos reikšmės SHA-512/256 algoritmui.
initial_sha_512_256_hash_values = [0x022312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151,
0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa,0x0eb72ddc81c52ca2]

def split_into_chunks(input):
  chunks = []
  input_length = len(input) * 8
  chunk_count = input_length // 896 + 1

  pre_process(input)


def pre_process(input):
    message_block = input
    input_length = len(input) * 8
    message_block += ((1 << 7).to_bytes(1, byteorder='little'))
    message_block.extend(bytearray((896 - (input_length % 896) - 8) // 8))
    message_block += (input_length).to_bytes(16, byteorder='big')
    for (i, char) in enumerate(message_block):
      if ((i + 1) % 4 == 0):
        print(format(char, '08b'))
      else:
        print(format(char, '08b'), end=' ')
    # print(message_block)
    return message_block

# split_into_chunks(input)

def main():
  with open('file.txt', 'rb') as file:
      input = bytearray(file.read())
      split_into_chunks(input)

if __name__ == "__main__":
    main()
