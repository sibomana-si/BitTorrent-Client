import json
import sys
import bencodepy
import requests


def decode_string(bencoded_value):
    try:
        return str(bencoded_value.split(b":")[1], "utf-8")
    except IndexError as e:
        print(f"Invalid encoded string: {bencoded_value} | {e}")
        raise e

def decode_int(bencoded_value):
    return int(bencoded_value[1:-1])

def decode_list(bencoded_value):
    pass

def decode_bencoded(bencoded_value):
    pass

def main():
    command = sys.argv[1]
    bc = bencodepy.Bencode(encoding='utf-8')

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoded_value = bc.decode(bencoded_value)
        print(json.dumps(decoded_value))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
