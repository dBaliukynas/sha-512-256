class Sha512_256:
  def __init__(self, input):
    self.message = input.copy()
    self.message_length = len(self.message) * 8
    self.chunk_size = 1024
    self.threshold = 895
    self.initial_sha_512_256_hash_values = [0x022312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151,
    0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa,0x0eb72ddc81c52ca2]

  def build_message_schedule(self):
    chunks = self.split_into_chunks()

    message_schedule = []

    for chunk in chunks:
      for i in range(16):
        # print(i)
        message_schedule.append(chunk[8 * i:8 * (i + 8)])

      for i in range(16, 80):
        sigma_0 = message_schedule[i - 15]
        sigma_1 = 2
        message_schedule.append(5)

    print(message_schedule)

  def split_into_chunks(self):
    self.message = self.pre_process()
    self.message_length = len(self.message) * 8

    chunk_count = self.message_length // self.chunk_size
    chunks = []

    for i in range(chunk_count):
      chunks.append(self.message[128 * i:128 * (i + 1)])

    # self.print_message_in_binary(chunk_count)

    return chunks

  def pre_process(self):

      self.message += ((1 << 7).to_bytes(1, byteorder='little'))
      padding_zeroes_length = (self.threshold - self.message_length) % self.chunk_size // 8
      self.message.extend(bytearray(padding_zeroes_length))
      self.message += (self.message_length).to_bytes(16, byteorder='big')

      return self.message

  def print_message_in_binary(self, chunk_count=None):
    for (i, char) in enumerate(self.message):
      if ((i + 1) % 4 == 0):
        print(format(char, '08b'))
      else:
        print(format(char, '08b'), end=' ')

    print(f'\nPadded message length in bits: {self.message_length}\n')
    print(f'\nPadded message length in bytes: {self.message_length // 8}\n')
    print(f'Amount of chunks: {chunk_count}')


def main():
  with open('file.txt', 'rb') as file:
      input = bytearray(file.read())
      sha_512_256 = Sha512_256(input)
      # sha_512_256.build_message_schedule()

  number = 0b11001010  # 202 in decimal
  bits_to_rotate = 3
  rotated_number = (number << 3) & 0xFFFFFFFF

  # rotated_number = (number >> bits_to_rotate) | (number << (8 - bits_to_rotate)) & 0xFF

  print(bin(rotated_number))  # Output: 0b01011001

if __name__ == "__main__":
    main()
