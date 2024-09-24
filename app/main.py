import json
import sys
from pathlib import Path
import hashlib
import requests
from urllib.parse import urlencode, quote_plus
#import bencodepy


def decode_bencoded(bencoded_value):
    decoded_container = []
    temp_list = []
    bencoded_length = len(bencoded_value)
    i = 0
    while i < bencoded_length:
        if bencoded_value[i:i+1] == b":":
            while len(decoded_container) != 0 and isinstance(decoded_container[-1], bytes):
                if decoded_container[-1].isascii() and decoded_container[-1].decode().isdigit():
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

def bencode_info_dict(info_dict: dict):
    bencoded_info_dict = b"d"
    for key, value in info_dict.items():
        bencoded_info_dict += f"{len(key)}:{key}".encode()
        if isinstance(value, int):
            bencoded_info_dict += f"i{value}e".encode()
        elif isinstance(value, str):
            bencoded_info_dict += f"{len(value)}:{value}".encode()
        elif isinstance(value, bytes):
            bencoded_info_dict += str(len(value)).encode() + b":" + value
        else:
            raise ValueError(f"invalid value type: {value} | {type(value)}")
    bencoded_info_dict += b"e"
    return bencoded_info_dict

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
    elif command in ("info", "peers"):
        meta_info_file_name = sys.argv[2]
        if meta_info_file_name.endswith(".torrent"):
            meta_info_file = Path(meta_info_file_name)
            bencoded_value = meta_info_file.read_bytes()
        else:
            raise ValueError(f"Invalid file extension: {meta_info_file_name}")
    else:
        raise NotImplementedError(f"Unknown command {command}")

    first_char = chr(bencoded_value[0])
    if not first_char.isdigit() and not first_char.isalpha():
        raise ValueError(f"Invalid encoding type: {first_char} | {bencoded_value}")
    if first_char.isalpha() and first_char not in ("i", "l", "d"):
        raise ValueError(f"Invalid encoding character: {first_char} | {bencoded_value}")
    decoded_value = decode_bencoded(bencoded_value)
    if command in ("info", "peers") and isinstance(decoded_value, dict):
        tracker_url = decoded_value['announce']
        file_length = decoded_value['info']['length']
        bencoded_info_dict: bytes = bencode_info_dict(decoded_value["info"])
        info_hash = hashlib.sha1(bencoded_info_dict)
        piece_length = decoded_value['info']['piece length']
        piece_hashes = decoded_value["info"]["pieces"]

        if command == "info":
            print(f"Tracker URL: {tracker_url}")
            print(f"Length: {file_length}")
            print(f"Info Hash: {info_hash.hexdigest()}")
            print(f"Piece Length: {piece_length}")
            print("Piece Hashes: ")
            for i in range(0, len(piece_hashes), 20):
                print(f"{piece_hashes[i:i + 20].hex()}")
        else:
            peer_id = '00112233445566778899'
            port = 6881
            uploaded = downloaded = 0
            left = file_length
            compact = 1
            tracker_params = {"info_hash": info_hash.digest(), "peer_id": peer_id, "port": port, "uploaded": uploaded,
                              "downloaded": downloaded, "left": left, "compact": compact}
            encoded_tracker_params = urlencode(tracker_params, quote_via=quote_plus)
            tracker_url += f"?{encoded_tracker_params}"
            tracker_response = requests.get(tracker_url)
            tracker_response_dict: dict = decode_bencoded(tracker_response.content)
            peer_list = tracker_response_dict['peers']
            for i in range(0, len(peer_list), 6):
                ip = ".".join(str(byte) for byte in peer_list[i:i+4])
                port = int.from_bytes(peer_list[i+4:i+6], 'big')
                ip_address = f"{ip}:{port}"
                print(f"{ip_address}")
    else:
        print(json.dumps(decoded_value))


if __name__ == "__main__":
    main()
