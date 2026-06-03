import json
import sys
from pathlib import Path


def decode_bencoded(bencoded_value):
    decoded_container = []
    temp_list = []
    bencoded_length = len(bencoded_value)
    i = 0

    while i < bencoded_length:
        if bencoded_value[i:i+1] == b":":
            while len(decoded_container) != 0 and isinstance(decoded_container[-1], bytes):
                if decoded_container[-1].decode().isdigit():
                    temp_list.append(decoded_container.pop().decode())
                else:
                    break
            len_digits = "".join(temp_list[::-1])
            encoded_string = bencoded_value[i+1:i+1+int(len_digits)]
            if encoded_string.isascii():
                decoded_string = str(encoded_string, "utf-8")
            else:
                decoded_string = encoded_string
            decoded_container.append(decoded_string)
            i += int(len_digits)
        elif bencoded_value[i:i+1] == b"e":
            while len(decoded_container) != 0 and decoded_container[-1] not in [b"i", b"l", b"d"]:
                temp_list.append(decoded_container.pop())
            if decoded_container[-1] == b"i":
                decoded_container.pop()
                decoded_int = int(b"".join(temp_list[::-1]))
                decoded_container.append(decoded_int)
            elif decoded_container[-1] == b"l":
                decoded_container.pop()
                decoded_container.append(temp_list[::-1])
            elif decoded_container[-1] == b"d":
                decoded_container.pop()
                decoded_dict = {}
                temp_list = temp_list[::-1]
                if len(temp_list) % 2 != 0:
                    raise ValueError(f"Invalid dict items count: {temp_list} | {bencoded_value}")
                for j in range(0, len(temp_list), 2):
                    if not isinstance(temp_list[j], str):
                        raise ValueError(f"Invalid dict key: {temp_list[j]} | {temp_list} | {bencoded_value}")
                    decoded_dict[temp_list[j]] = temp_list[j+1]
                decoded_container.append(decoded_dict)
            else:
                raise ValueError(f"Invalid encoding character: {bencoded_value} | {decoded_container} ")
        else:
            decoded_container.append(bencoded_value[i:i+1])
        temp_list = []
        i += 1

    return decoded_container[0]


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        first_char = chr(bencoded_value[0])

        if not first_char.isdigit() and not first_char.isalpha():
            raise ValueError(f"Invalid encoding type: {first_char} | {bencoded_value}")

        decoded_value = decode_bencoded(bencoded_value)
        print(json.dumps(decoded_value))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
