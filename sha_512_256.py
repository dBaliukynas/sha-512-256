# Pirminės maišos reikšmės SHA-512/256 algoritmui.
initial_sha_512_256_hash_values = [0x022312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151,
0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa,0x0eb72ddc81c52ca2]

def split_into_chunks(input):
  chunks = []

  pre_process(input)


def pre_process(input):
    message_block = input
    input_length = len(input) * 8
    print(input_length)

    message_block += ((1 << 7).to_bytes(1, byteorder='little'))
    padding_zeroes_length = (895 - input_length) % 1024 // 8
    message_block.extend(bytearray(padding_zeroes_length))
    message_block += (input_length).to_bytes(16, byteorder='big')

    print(len(message_block))

    print_message_block(message_block)

    return message_block

def print_message_block(message_block):
  for (i, char) in enumerate(message_block):
    if ((i + 1) % 4 == 0):
      print(format(char, '08b'))
    else:
      print(format(char, '08b'), end=' ')


# split_into_chunks(input)

def main():
  with open('file.txt', 'rb') as file:
      input = bytearray(file.read())
      split_into_chunks(input)

if __name__ == "__main__":
    main()
