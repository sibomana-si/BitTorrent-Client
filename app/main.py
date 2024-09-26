import json
import sys
from pathlib import Path
import hashlib
import requests
import socket
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

def get_meta_info(decoded_value: dict):
    meta_info = {}
    meta_info["Tracker URL"] = decoded_value["announce"]
    meta_info["Length"] = decoded_value["info"]["length"]
    meta_info["Info Hash"] = hashlib.sha1(bencode_info_dict(decoded_value["info"]))
    meta_info["Piece Length"] = decoded_value["info"]["piece length"]
    piece_hashes = decoded_value["info"]["pieces"]
    piece_hashes_list = []
    for i in range(0, len(piece_hashes), 20):
        piece_hashes_list.append(piece_hashes[i:i + 20].hex())
    meta_info["Piece Hashes"] = piece_hashes_list
    return meta_info

def get_peer_list(meta_info: dict, peer_id:str):
    peer_list = []
    tracker_url = meta_info["Tracker URL"]
    info_hash = meta_info["Info Hash"]
    port = 6881
    uploaded = downloaded = 0
    left = meta_info["Length"]
    compact = 1
    tracker_params = {"info_hash": info_hash.digest(), "peer_id": peer_id, "port": port, "uploaded": uploaded,
                      "downloaded": downloaded, "left": left, "compact": compact}
    encoded_tracker_params = urlencode(tracker_params, quote_via=quote_plus)
    tracker_url += f"?{encoded_tracker_params}"
    tracker_response = requests.get(tracker_url)
    tracker_response_dict: dict = decode_bencoded(tracker_response.content)
    peer_addresses = tracker_response_dict['peers']
    for i in range(0, len(peer_addresses), 6):
        ip = ".".join(str(byte) for byte in peer_addresses[i:i + 4])
        port = int.from_bytes(peer_addresses[i + 4:i + 6], 'big')
        ip_address = f"{ip}:{port}"
        peer_list.append(ip_address)

    return peer_list

def perform_handshake(meta_info: dict, peer_list: list, peer_ip: str, peer_port: str, peer_id: str, peer_socket: socket):
    protocol_name = b"BitTorrent protocol"
    protocol_name_length = len(protocol_name)
    reserved_bytes = 0
    info_hash = meta_info["Info Hash"]
    handshake_message = (protocol_name_length.to_bytes(1, 'big') + protocol_name
                         + reserved_bytes.to_bytes(8, 'big') + info_hash.digest() + peer_id.encode())
    peer_socket.connect((peer_ip, int(peer_port)))
    peer_socket.sendall(handshake_message)
    peer_response = peer_socket.recv(68)
    return peer_response

def download_piece(piece_index: int, meta_info: dict, peer_socket: socket, piece_outfile: Path):
    block_size = 2**14
    byte_length = 4
    block_reqs = []
    piece_blocks = []
    total_file_length = meta_info["Length"]
    piece_length = meta_info["Piece Length"]
    piece_hashes_list = meta_info["Piece Hashes"]
    piece_hash = piece_hashes_list[piece_index]

    if piece_index == (len(piece_hashes_list) - 1) and total_file_length % piece_length != 0:
        piece_size = total_file_length % piece_length
    else:
        piece_size = piece_length

    bitfield_message = peer_socket.recv(20)
    interested_message = int.to_bytes(1, 4, 'big') + int.to_bytes(2, 1, 'big')
    peer_socket.sendall(interested_message)
    unchoke_message = peer_socket.recv(5)

    block_index = int.to_bytes(piece_index, byte_length, 'big')
    block_length = int.to_bytes(block_size, byte_length, 'big')
    for i in range(piece_size // block_size):
        block_begin = int.to_bytes(i * block_size, byte_length, 'big')
        block = block_index + block_begin + block_length
        block_reqs.append(block)

    if piece_size % block_size != 0:
        block_begin = int.to_bytes((piece_size // block_size) * block_size, byte_length, 'big')
        block_length = int.to_bytes((piece_size % block_size), byte_length, 'big')
        block = block_index + block_begin + block_length
        block_reqs.append(block)

    for block_req in block_reqs:
        piece_block = b""
        request_message = (int.to_bytes(13, 4, 'big') + int.to_bytes(6, 1, 'big')
                           + block_req)
        peer_socket.sendall(request_message)
        piece_block_size = int.from_bytes(request_message[-4:], 'big')
        buf_size = 2048

        while True:
            received_data = peer_socket.recv(buf_size)
            piece_block += received_data
            if len(received_data) < buf_size and len(piece_block) >= piece_block_size:
                break

        piece_blocks.append(piece_block[13:])

    downloaded_piece = b"".join(piece_blocks)
    downloaded_piece_hash = hashlib.sha1(downloaded_piece).hexdigest()
    if downloaded_piece_hash != piece_hash:
        raise ValueError(f"Invalid piece hash: {downloaded_piece_hash} | {piece_hash}")
    else:
        print(f"valid piece hash: {downloaded_piece_hash} | {piece_hash}")
        piece_outfile.write_bytes(downloaded_piece)

    return

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
    elif command in ("info", "peers", "handshake", "download_piece"):
        if command == "download_piece":
            meta_info_file_name = sys.argv[4]
        else:
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
    if command in ("info", "peers", "handshake", "download_piece") and isinstance(decoded_value, dict):
        peer_id = '00112233445566778899'

        if command == "info":
            meta_info: dict = get_meta_info(decoded_value)
            print(f"Tracker URL: {meta_info['Tracker URL']}")
            print(f"Length: {meta_info['Length']}")
            print(f"Info Hash: {meta_info['Info Hash'].hexdigest()}")
            print(f"Piece Length: {meta_info['Piece Length']}")
            print("Piece Hashes: ")
            print("\n".join(meta_info["Piece Hashes"]))
        elif command == "peers":
            meta_info: dict = get_meta_info(decoded_value)
            peer_list: list = get_peer_list(meta_info, peer_id)
            print(f"\n".join(peer_list))
        elif command == "handshake":
            try:
                peer_ip, peer_port = sys.argv[3].split(":")
                meta_info: dict = get_meta_info(decoded_value)
                peer_list: list = get_peer_list(meta_info, peer_id)
                peer_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                handshake_response: bytes = perform_handshake(meta_info, peer_list, peer_ip, peer_port, peer_id, peer_socket)
                peer_response_id = handshake_response[-20:].hex()
                print(f"Peer ID: {peer_response_id}")
                peer_socket.close()
            except Exception as e:
                print(e)
        elif command == "download_piece":
            try:
                piece_index = int(sys.argv[5])
                piece_outfile = Path(sys.argv[3])
                print(f"downloading piece_index: {piece_index} ...")
                meta_info: dict = get_meta_info(decoded_value)
                peer_list: list = get_peer_list(meta_info, peer_id)
                peer_ip, peer_port = peer_list[0].split(":")
                peer_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                handshake_response: bytes = perform_handshake(meta_info, peer_list, peer_ip, peer_port, peer_id,
                                                          peer_socket)
                download_piece(piece_index, meta_info, peer_socket, piece_outfile)
                print(f"piece_{piece_index} downloaded to {piece_outfile}")
                peer_socket.close()
            except Exception as e:
                print(e)

    else:
        print(json.dumps(decoded_value))


if __name__ == "__main__":
    main()
