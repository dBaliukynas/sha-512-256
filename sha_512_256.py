class Sha512_256:
    def __init__(self, input):
        self.message = input.copy()
        self.message_length = len(self.message) * 8
        self.chunk_size = 1024
        self.threshold = 895

        self.initial_sha_512_256_hash_values = [
            0x022312194FC2BF72C,
            0x9F555FA3C84C64C2,
            0x2393B86B6F53B151,
            0x963877195940EABD,
            0x96283EE2A88EFFE3,
            0xBE5E1E2553863992,
            0x2B0199FC2C85B8AA,
            0x0EB72DDC81C52CA2,
        ]

        self.round_constants = [
            0x428A2F98D728AE22,
            0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F,
            0xE9B5DBA58189DBBC,
            0x3956C25BF348B538,
            0x59F111F1B605D019,
            0x923F82A4AF194F9B,
            0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242,
            0x12835B0145706FBE,
            0x243185BE4EE4B28C,
            0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F,
            0x80DEB1FE3B1696B1,
            0x9BDC06A725C71235,
            0xC19BF174CF692694,
            0xE49B69C19EF14AD2,
            0xEFBE4786384F25E3,
            0x0FC19DC68B8CD5B5,
            0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275,
            0x4A7484AA6EA6E483,
            0x5CB0A9DCBD41FBD4,
            0x76F988DA831153B5,
            0x983E5152EE66DFAB,
            0xA831C66D2DB43210,
            0xB00327C898FB213F,
            0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2,
            0xD5A79147930AA725,
            0x06CA6351E003826F,
            0x142929670A0E6E70,
            0x27B70A8546D22FFC,
            0x2E1B21385C26C926,
            0x4D2C6DFC5AC42AED,
            0x53380D139D95B3DF,
            0x650A73548BAF63DE,
            0x766A0ABB3C77B2A8,
            0x81C2C92E47EDAEE6,
            0x92722C851482353B,
            0xA2BFE8A14CF10364,
            0xA81A664BBC423001,
            0xC24B8B70D0F89791,
            0xC76C51A30654BE30,
            0xD192E819D6EF5218,
            0xD69906245565A910,
            0xF40E35855771202A,
            0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8,
            0x1E376C085141AB53,
            0x2748774CDF8EEB99,
            0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63,
            0x4ED8AA4AE3418ACB,
            0x5B9CCA4F7763E373,
            0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC,
            0x78A5636F43172F60,
            0x84C87814A1F0AB72,
            0x8CC702081A6439EC,
            0x90BEFFFA23631E28,
            0xA4506CEBDE82BDE9,
            0xBEF9A3F7B2C67915,
            0xC67178F2E372532B,
            0xCA273ECEEA26619C,
            0xD186B8C721C0C207,
            0xEADA7DD6CDE0EB1E,
            0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA,
            0x0A637DC5A2C898A6,
            0x113F9804BEF90DAE,
            0x1B710B35131C471B,
            0x28DB77F523047D84,
            0x32CAAB7B40C72493,
            0x3C9EBE0A15C9BEBC,
            0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6,
            0x597F299CFC657E2A,
            0x5FCB6FAB3AD6FAEC,
            0x6C44198C4A475817,
        ]

    def truncate_to_64_bits(self, word):
      return word & 0xFFFFFFFFFFFFFFFF

    def rotr(self, word, bits_to_rotate):
        word_int = int.from_bytes(word, byteorder="big")
        rotated_word = self.truncate_to_64_bits((
            (word_int >> bits_to_rotate) | (word_int << 64 - bits_to_rotate)
        ))
        return rotated_word

    def build_message_schedule(self):
        chunks = self.split_into_chunks()

        message_schedule = []

        for chunk in chunks:
            for i in range(16):
                message_schedule.append(chunk[8 * i : 8 * (i + 8)])

            for i in range(16, 80):
                sigma_0 = (
                    self.rotr(message_schedule[i - 15], 1)
                    ^ self.rotr(message_schedule[i - 15], 8)
                    ^ (int.from_bytes(message_schedule[i - 15], byteorder="big") >> 7)
                )
                sigma_1 = (
                    self.rotr(message_schedule[i - 2], 19)
                    ^ self.rotr(message_schedule[i - 2], 61)
                    ^ (int.from_bytes(message_schedule[i - 2], byteorder="big") >> 6)
                )
                message_schedule.append(
                    message_schedule[i - 16]
                    + (self.truncate_to_64_bits(sigma_0)).to_bytes(8, byteorder="big")
                    + message_schedule[i - 7]
                    + (self.truncate_to_64_bits(sigma_1)).to_bytes(8, byteorder="big")
                )

        # print(message_schedule)

    def split_into_chunks(self):
        self.message = self.pre_process()
        self.message_length = len(self.message) * 8

        chunk_count = self.message_length // self.chunk_size
        chunks = []

        for i in range(chunk_count):
            chunks.append(self.message[128 * i : 128 * (i + 1)])

        # self.print_message_in_binary(chunk_count)

        return chunks

    def pre_process(self):

        self.message += (1 << 7).to_bytes(1, byteorder="little")
        padding_zeroes_length = (
            (self.threshold - self.message_length) % self.chunk_size // 8
        )
        self.message.extend(bytearray(padding_zeroes_length))
        self.message += (self.message_length).to_bytes(16, byteorder="big")

        return self.message

    def print_message_in_binary(self, chunk_count=None):
        for (i, char) in enumerate(self.message):
            if (i + 1) % 4 == 0:
                print(format(char, "08b"))
            else:
                print(format(char, "08b"), end=" ")

        print(f"\nPadded message length in bits: {self.message_length}\n")
        print(f"\nPadded message length in bytes: {self.message_length // 8}\n")
        print(f"Amount of chunks: {chunk_count}")


def main():
    with open("file.txt", "rb") as file:
        input = bytearray(file.read())
        sha_512_256 = Sha512_256(input)
        sha_512_256.build_message_schedule()

if __name__ == "__main__":
    main()
