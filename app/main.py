import json
import sys

#import bencodepy
#import requests


def decode_bencode(bencoded_value):
    first_char = chr(bencoded_value[0])
    last_char = chr(bencoded_value[-1])

    if first_char.isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        return str(bencoded_value[first_colon_index+1:], "utf-8")
    elif first_char == "i" and last_char == "e":
        return int(bencoded_value[1:-1])
    else:
        raise NotImplementedError("Only strings are supported at the moment")


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        print(json.dumps(decode_bencode(bencoded_value)))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
