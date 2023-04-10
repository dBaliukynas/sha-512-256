import argparse


class Sha512_256:
    """Klasė, skirta SHA512/256 maišos reikšmės apskaičiavimui.

    Kintamieji
    ----------
    options : argparse.Namespace
                    Komandinės eilutės argumentų reikšmės.
    message : bytearray
                    Žinutė baitų masyve.
    message_length : int
                    Žinutės ilgis bitais.
    chunk_size : int
                    Žinutės dalies (chunk) dydis bitais.
    threshold: int
        Riba bitais, kada žinutė turi būti praplėsta papildomais 1024 bitais.
    initial_sha_512_256_hash_values : list of int
                    Sąrašas pradinių reikšmių, skirtų SHA512/256 maišos reikšmės apskaičiavimui.
    round_constants : list of int
                    Sąrašas konstantų, skirtų SHA512 maišos reikšmėms apskaičiuoti.
    """

    def __init__(self, args):
        """Sukonstruoja Sha512_256 klasės objektą.

        Parametrai
        ----------
        args : argparse.Namespace
            Komandinės eilutės argumentų reikšmės.
        """

        self.options = args
        self.message = self.read_from_file().copy()
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
        """Sutrumpina paduotą word reikšmę į 64 bitų reikšmę.

        Parametrai
        ----------
        word : int
            Bitai paversti skaičiumi.

        Grąžina
        -------
        int
            64 bitų reikšmė paversta skaičiumi.
        """
        return word & 0xFFFFFFFFFFFFFFFF

    def rotate_to_right(self, word, bits_to_rotate):
        """Pasuka (circular-shift) paduotą word reikšmę į kairę bits_to_rotate kartų.

        Parametrai
        ----------
        word : int
            Bitai paversti skaičiumi.
        bits_to_rotate : int
            Pasukimų kiekis.

        Grąžina
        -------
        int
            64 bitų reikšmė paversta skaičiumi ir pasukta bits_to_rotate kartų.
        """
        return self.truncate_to_64_bits(
            ((word >> bits_to_rotate) | (word << 64 - bits_to_rotate))
        )

    def print_result(self, digested_message):
        """Atspausdina maišos reikšmę komandinėje eilutėje.

        Parametrai
        ----------
        digested_message : bytearray
            Maišos reikšmė, sujungta iš atskirų suglaudintų žinutės dalių ir sutrumpinta iki 256 bitų.
        """

        def print_pipe_symbols():
            """Atspausdina strypų (║) simbolius komandinėje eilutėje.
            Grąžina
            -------
            NoneType
                print() metodo reikšmė.

            """
            return print(f'║{" " * 68}║')

        if self.options.upper_case:
            digested_message = digested_message.hex().upper()
        else:
            digested_message = digested_message.hex()

        if not self.options.simplify:
            print(f"\n╔{'═' * 68}╗")
            print_pipe_symbols()
            print(f"║ SHA512/256 Hash result:{' ' * 44}║")
            print_pipe_symbols()

            print("║ " + digested_message + "   ║")

            print_pipe_symbols()
            print(f"╚{'═' * 68}╝\n")

        else:
            print(digested_message)

    def digest(self, compressed_chunks):
        """Apjungia kiekvieną suglaudintą compressed_chunks elementą ir taip suformuoja galutinę maišos reikšmę.

        Parametrai
        ----------
        compressed_chunks : list of int
            Suglaudintų žinutės dalių sąrašas.

        Grąžina
        -------
        digested_message[:32]: bytearray
            Maišos reikšmė, sujungta iš atskirų suglaudintų žinutės dalių ir sutrumpinta iki 256 bitų.
        """

        digested_message = bytearray()

        for i in range(len(compressed_chunks)):
            digested_message.extend(compressed_chunks[i].to_bytes(8, byteorder="big"))

        return digested_message[:32]

    def compute_hash(self):
        """Suskaičiuoja maišos reikšmę.

        Grąžina
        -------
        bytearray
            Maišos reikšmė, sujungta iš atskirų suglaudintų žinutės dalių ir sutrumpinta iki 256 bitų.
        """
        return self.digest(self.create_compressed_chunks(self.split_into_chunks()))

    def create_compressed_chunks(self, chunks):
        """Sukuria suglaudintų žinutės dalių (chunks) sąrašą.

        Parametrai
        ----------
        chunks : list of bytearray
            1024 bitų dydžio žinutės dalių sąrašas.

        Grąžina
        -------
        compressed_chunks : list of int
            Suglaudintų žinutės dalių sąrašas
        """

        working_variables = [0] * 8
        working_variables_length = len(working_variables)

        for (i, initial_hash_value) in enumerate(self.initial_sha_512_256_hash_values):
            working_variables[i] = initial_hash_value

        compressed_chunks = working_variables.copy()

        for chunk in chunks:
            message_schedule = self.create_message_schedule(chunk)

            for i in range(working_variables_length):
                working_variables[i] = compressed_chunks[i]

            working_variables = self.compress(working_variables, message_schedule)

            for i in range(working_variables_length):
                compressed_chunks[i] = self.truncate_to_64_bits(
                    compressed_chunks[i] + working_variables[i]
                )

        return compressed_chunks

    def compress(self, working_variables, message_schedule):
        """Atlieka seriją loginių ir aritmetinių operacijų ir atnaujina
           kintamųjų (working_variables) reikšmes taip, kad net ir menkiausias
           žinutės pokytis smarkiai pakeistų maišos reikšmę.

        Parametrai
        ----------
        working_variables : list of int
            Kintamųjų sąrašas, kurio reikšmės naudojamos maišos reikšmei suskaičiuoti.
        message_schedule : list of int
            Iš žinutės dalių (chunks) sukurtas žodžių (words) sąrašas.

        Grąžina
        -------
        working_variables: list of int
            Kintamųjų sąrašas, kurio reikšmės naudojamos maišos reikšmei suskaičiuoti.
        """

        for i in range(80):
            sum_1 = (
                self.rotate_to_right(working_variables[4], 14)
                ^ self.rotate_to_right(working_variables[4], 18)
                ^ self.rotate_to_right(working_variables[4], 41)
            )
            choice = (working_variables[4] & working_variables[5]) ^ (
                (~working_variables[4]) & working_variables[6]
            )
            temporary_1 = (
                working_variables[7]
                + sum_1
                + choice
                + self.round_constants[i]
                + message_schedule[i]
            )

            sum_0 = (
                self.rotate_to_right(working_variables[0], 28)
                ^ self.rotate_to_right(working_variables[0], 34)
                ^ self.rotate_to_right(working_variables[0], 39)
            )
            majority = (
                (working_variables[0] & working_variables[1])
                ^ (working_variables[0] & working_variables[2])
                ^ (working_variables[1] & working_variables[2])
            )
            temporary_2 = sum_0 + majority

            for i in range(len(working_variables) - 1, -1, -1):
                working_variables[i] = working_variables[i - 1]
                if i == 4:
                    working_variables[i] = self.truncate_to_64_bits(
                        working_variables[i - 1] + temporary_1
                    )
                if i == 0:
                    working_variables[0] = self.truncate_to_64_bits(
                        temporary_1 + temporary_2
                    )

        return working_variables

    def create_message_schedule(self, chunk):
        """Sukuria žinutės tvarkaraštį (message_schedule) -- padalina žinutės dalį (chunk) į
           64 bitų dydžio žodžius (words) ir atnaujina žinutės tvarkaraštį, atliekant įvairias
           logines ir aritmetines operacijas.

        Parametrai
        ----------
        chunk : bytearray
            1024 bitų dydžio žinutės dalis.

        Grąžina
        -------
        message_schedule : list of int
            Iš žinutės dalių (chunks) sukurtas žodžių (words) sąrašas.
        """

        message_schedule = [0] * 80
        for i in range(16):
            message_schedule[i] = int.from_bytes(
                chunk[8 * i : 8 * (i + 1)], byteorder="big"
            )

        for i in range(16, 80):
            sigma_0 = (
                self.rotate_to_right(message_schedule[i - 15], 1)
                ^ self.rotate_to_right(message_schedule[i - 15], 8)
                ^ message_schedule[i - 15] >> 7
            )
            sigma_1 = (
                self.rotate_to_right(message_schedule[i - 2], 19)
                ^ self.rotate_to_right(message_schedule[i - 2], 61)
                ^ message_schedule[i - 2] >> 6
            )
            message_schedule[i] = self.truncate_to_64_bits(
                message_schedule[i - 16] + sigma_0 + message_schedule[i - 7] + sigma_1
            )

        return message_schedule

    def split_into_chunks(self):
        """Padalina žinutę į 1024 bitų dydžio dalis (chunks).

        Grąžina
        -------
        chunks : list of bytearray
            1024 bitų dydžio žinutės dalių sąrašas.
        """

        self.message = self.pre_process()
        self.message_length = len(self.message) * 8

        chunk_count = self.message_length // self.chunk_size
        chunks = []

        for i in range(chunk_count):
            chunks.append(self.message[128 * i : 128 * (i + 1)])

        if self.options.print_message:
            self.print_message_in_binary(chunk_count)
        return chunks

    def pre_process(self):
        """Modifikuoja (suformatuoja) žinutę -- prideda bitą "1" prie žinutės pabaigos,
           prideda "0" bitų iki kol žinutė pasiekia 896 bitų ilgį. Galiausiai, likusieji
           128 bitai reprezentuoja žinutės ilgį.

        Grąžina
        -------
        message : bytearray
            Modifikuota (suformatuota) žinutė.
        """

        self.message.extend((1 << 7).to_bytes(1, byteorder="little"))
        padding_zeroes_length = (
            (self.threshold - self.message_length) % self.chunk_size // 8
        )
        self.message.extend(bytearray(padding_zeroes_length))
        self.message.extend((self.message_length).to_bytes(16, byteorder="big"))

        return self.message

    def print_message_in_binary(self, chunk_count=None):
        """Spausdina žinutę dvejetainiu formatu komandinėje eilutėje.

        Parametrai
        -------
        chunk_count : int
            Žinutės dalių (chunks) kiekis.
        """

        for (i, byte) in enumerate(self.message):
            if i % 128 == 0:
                print("")
            if (i + 1) % 4 == 0:
                print(format(byte, "08b"))
            else:
                print(format(byte, "08b"), end=" ")

        print(f"\nPadded message length in bits: {self.message_length}\n")
        print(f"\nPadded message length in bytes: {self.message_length // 8}\n")
        print(f"Amount of chunks: {chunk_count}")

    def print_error_message(self, error_message):
        """Spausdina klaidos žinutę komandinėje eilutėje.

        Parametrai
        -------
        error_message : str
            Klaidos žinutė.
        """

        print("\x1b[1;41m" + f"\n{error_message}" + "\x1b[m\n")

    def write_to_file(self, digested_message):
        """Įrašo galutinę maišos reikšmę į failą.

        Parametrai
        -------
        digested_message : bytearray
            Maišos reikšmė, sujungta iš atskirų suglaudintų žinutės dalių ir sutrumpinta iki 256 bitų.
        """

        try:
            with open(self.options.output_filename, "w") as file:
                if self.options.upper_case:
                    file.write(digested_message.hex().upper())
                else:
                    file.write(digested_message.hex())
        except IsADirectoryError:
            self.print_error_message(
                f"Failas {self.options.output_filename} yra katalogas."
            )
            raise SystemExit(1)
        except PermissionError:
            self.print_error_message(
                f"Nėra suteiktos privilegijos rašyti į failą {self.options.output_filename}."
            )
            raise SystemExit(1)

    def read_from_file(self):
        """Skaito duomenis iš failo dvejetainiu formatu.

        Grąžina
        -------
        input : bytearray
            Failo turinys baitų masyve.
        """

        input = bytearray()

        try:
            with open(self.options.input_filename, "rb") as file:
                input.extend(file.read())
        except FileNotFoundError:
            self.print_error_message(f"Failas {self.options.input_filename} nerastas.")
            raise SystemExit(1)
        except IsADirectoryError:
            self.print_error_message(
                f"Failas {self.options.input_filename} yra katalogas."
            )
            raise SystemExit(1)
        except PermissionError:
            self.print_error_message(
                f"Nėra suteiktos privilegijos skaityti failą {self.options.input_filename}."
            )
            raise SystemExit(1)

        return input


def parse_arguments():
    """Sukuria ir apdoroja komandinės eilutės argumentus.

    Grąžina
    -------
    argparse.Namespace
        Komandinės eilutės argumentų reikšmės.
    """

    parser = argparse.ArgumentParser(
        description="Programa, suskaičiuojanti ir grąžinanti SHA512/256 maišos reikšmę."
    )
    parser.add_argument(
        "-if",
        "--input-filename",
        metavar="[failo pavadinimas]",
        type=str,
        required=True,
        help="Failo, iš kurio turinio bus suskaičiuojama maišos reikšmė, pavadinimas",
    )
    parser.add_argument(
        "-of",
        "--output-filename",
        metavar="[failo pavadinimas]",
        type=str,
        help="Failo, kuriame bus saugoma suskaičiuota maišos reikšmė, pavadinimas",
    )
    parser.add_argument(
        "-oc",
        "--output-cli",
        action="store_true",
        help="Nustatymas, kuris nurodo, ar maišos reikšmė bus atvaizduojama komandinėje eilutėje, kai jau yra nurodytas išvesties failas.",
    )
    parser.add_argument(
        "-pm",
        "--print-message",
        action="store_true",
        help="Nustatymas, kuris nurodo, ar atvaizduoti suformatuotą failo turinį bitais komandinėje eilutėje.",
    )
    parser.add_argument(
        "-uc",
        "--upper-case",
        action="store_true",
        help="Nustatymas, kuris nurodo, ar atvaizduoti ir saugoti maišos reikšmę didžiosomis raidėmis.",
    )
    parser.add_argument(
        "-s",
        "--simplify",
        action="store_true",
        help="Nustatymas, kuris nurodo, ar atvaizduoti maišos reikšmę komandinėje eilutėje kaip paprastą eilutę (string).",
    )

    return parser.parse_args()


def main():
    """Apskaičiuoja maišos reikšmę ir išveda rezultatą į ekraną ir/arba failą."""
    args = parse_arguments()

    sha_512_256 = Sha512_256(args)

    hash = sha_512_256.compute_hash()

    if args.output_filename:
        sha_512_256.write_to_file(hash)
    if args.output_cli or args.output_filename is None:
        sha_512_256.print_result(hash)


if __name__ == "__main__":
    main()
