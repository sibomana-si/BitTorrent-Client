import json
import sys
import hashlib
import requests
import socket
import logging
import time
from pathlib import Path
from sys import meta_path
from urllib.parse import urlencode, quote_plus, unquote_plus
#import bencodepy


def get_bencoded(command:str) -> bytes:
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
    elif command in ("info", "peers", "handshake"):
        meta_info_file_name = sys.argv[2]
        bencoded_value = validate_metainfo_filename(meta_info_file_name)
    elif command in ("download_piece", "download"):
        meta_info_file_name = sys.argv[4]
        bencoded_value = validate_metainfo_filename(meta_info_file_name)
    else:
        raise NotImplementedError(f"unknown command {command}")
    return bencoded_value

def validate_bencoded(bencoded_value: bytes):
    first_char = chr(bencoded_value[0])
    if not first_char.isdigit() and not first_char.isalpha():
        raise ValueError(f"Invalid encoding type: {first_char} | {bencoded_value}")
    if first_char.isalpha() and first_char not in ("i", "l", "d"):
        raise ValueError(f"Invalid encoding character: {first_char} | {bencoded_value}")

def validate_metainfo_filename(meta_info_file_name: str) -> bytes:
    if meta_info_file_name.endswith(".torrent"):
        meta_info_file = Path(meta_info_file_name)
        bencoded_value = meta_info_file.read_bytes()
        return bencoded_value
    else:
        raise ValueError(f"Invalid file extension: {meta_info_file_name}")

def decode_bencoded(bencoded_value: bytes):
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

def bencode_info_dict(info_dict: dict) -> bytes:
    bencoded_info_dict = b"d"
    for key, value in info_dict.items():
        bencoded_info_dict += f"{len(key)}:{key}".encode()
        if isinstance(value, int):
            bencoded_info_dict += f"i{value}e".encode()
        elif isinstance(value, str):
            bencoded_info_dict += f"{len(value)}:{value}".encode()
        elif isinstance(value, bytes):
            bencoded_info_dict += str(len(value)).encode() + b":" + value
        elif isinstance(value, dict):
            bencoded_info_dict += bencode_info_dict(value)
        else:
            raise ValueError(f"invalid value type: {value} | {type(value)}")
    bencoded_info_dict += b"e"
    return bencoded_info_dict

def get_meta_info(bencoded_value: bytes) -> dict:
    meta_info = {}
    decoded_value: dict = decode_bencoded(bencoded_value)
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

def get_peer_list(meta_info: dict) -> list:
    peer_list = []
    tracker_url = meta_info["Tracker URL"]
    info_hash = meta_info["Info Hash"] if type(meta_info["Info Hash"]) == bytes else meta_info["Info Hash"].digest()
    port = 6881
    uploaded = downloaded = 0
    left = meta_info["Length"]
    compact = 1
    tracker_params = {"info_hash": info_hash, "peer_id": peer_id, "port": port, "uploaded": uploaded,
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

def connect_to_peer(peer_socket: socket, peer_index: int, peer_list: list) -> None:
    try:
        peer_ip, peer_port = peer_list[peer_index].split(":")
        peer_socket.connect((peer_ip, int(peer_port)))
        print(f"connected to {peer_ip}:{peer_port}")
    except Exception as e:
        if peer_index == (len(peer_list) - 1):
            print(f"failed to connect to all peers!")
            raise e
        else:
            connect_to_peer(peer_socket, peer_index + 1, peer_list)

def perform_handshake(meta_info: dict, peer_list: list, magnet: bool=False) -> tuple[socket, bytes]:
    try:
        protocol_name = b"BitTorrent protocol"
        protocol_name_length = len(protocol_name)
        reserved_bytes = 1048576 if magnet else 0
        info_hash = meta_info["Info Hash"] if type(meta_info["Info Hash"]) == bytes else meta_info["Info Hash"].digest()

        peer_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect_to_peer(peer_socket, 0, peer_list)

        handshake_message = (protocol_name_length.to_bytes(1, 'big') + protocol_name
                         + reserved_bytes.to_bytes(8, 'big') + info_hash
                         + peer_id.encode())
        peer_socket.sendall(handshake_message)
        peer_response = peer_socket.recv(68)
        return peer_socket, peer_response
    except Exception as e:
        print("exception in perform_handshake")
        raise e

def download_piece(meta_info: dict, peer_socket: socket, piece_index: int) -> bytes:
    try:
        print(f"downloading piece_index: {piece_index} ...")
        block_size = 2 ** 14
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

        for i in range(0, len(block_reqs), 4):
            piece_block_sizes = []
            for block_req in block_reqs[i:i + 4]:
                
                request_message = (int.to_bytes(13, 4, 'big')
                                   + int.to_bytes(6, 1, 'big') + block_req)
                peer_socket.sendall(request_message)
                piece_block_size = 13 + int.from_bytes(request_message[-4:], 'big')
                piece_block_sizes.append(piece_block_size)

            for piece_block_size in piece_block_sizes:
                buf_size = 1024
                piece_block = b""
                while True:
                    if piece_block_size - len(piece_block) < buf_size:
                        piece_block += peer_socket.recv(piece_block_size - len(piece_block))
                        break
                    received_data = peer_socket.recv(buf_size)
                    piece_block += received_data

                piece_blocks.append(piece_block[13:])

        downloaded_piece = b"".join(piece_blocks)
        downloaded_piece_hash = hashlib.sha1(downloaded_piece).hexdigest()
        if downloaded_piece_hash != piece_hash:
            raise ValueError(f"Invalid piece hash: {downloaded_piece_hash} | {piece_hash}")
        else:
            print(f"valid piece hash: {downloaded_piece_hash} | {piece_hash}")

        return downloaded_piece
    except Exception as e:
        print("exception in download_piece")
        raise e

def download_file(meta_info: dict, peer_socket: socket) -> None:
    try:
        torrent_outfile = Path(sys.argv[3])
        print(f"downloading to {torrent_outfile} ...")
        print(f"pieces to download: {len(meta_info['Piece Hashes'])}")
        file_data = b""

        for piece_index in range(len(meta_info["Piece Hashes"])):
            downloaded_piece: bytes = download_piece(meta_info, peer_socket, piece_index)
            file_data += downloaded_piece
            print(f"piece_{piece_index} | {len(downloaded_piece)} downloaded.")

        with torrent_outfile.open('wb') as outfile:
            outfile.write(file_data)

    except Exception as e:
        print("exception in download_file")
        raise e

def parse_magnet_link(magnetic_link: str) -> dict:
    meta_info = {}
    if magnetic_link.startswith("magnet:?xt="):
        info_hash_index = magnetic_link.find("xt=urn:btih:")
        tracker_url_index = magnetic_link.find("tr=")
        if info_hash_index != -1 and tracker_url_index != -1:
            info_hash = magnetic_link[info_hash_index + 12:info_hash_index + 52]
            tracker_url = magnetic_link[tracker_url_index + 3:]
            meta_info["Info Hash"] = info_hash
            meta_info["Tracker URL"] = unquote_plus(tracker_url)
            return meta_info
        else:
            raise Exception(f"Missing Info Hash or Tracker URL: {magnetic_link}")
    else:
        raise Exception(f"Invalid magnetic link: {magnetic_link}")

def perform_extension_handshake(meta_info: dict) -> tuple[socket, dict]:
    meta_info["Info Hash"] = int(meta_info["Info Hash"], 16).to_bytes(20, 'big')
    meta_info["Length"] = 999  # arbitrary value
    peer_list: list = get_peer_list(meta_info)
    peer_socket, handshake_response = perform_handshake(meta_info, peer_list, True)
    peer_response_id = handshake_response[-20:].hex()
    bitfield_message = get_peer_response(peer_socket)
    peer_reserved_bytes = int.from_bytes(handshake_response[20:28], 'big')
    if peer_reserved_bytes != 0:
        handshake_dict = {"m": {"ut_metadata": 1}}
        xt_handshake_dict: bytes = bencode_info_dict(handshake_dict)
        xt_handshake_dict_size = len(xt_handshake_dict)
        xt_handshake_message = (int.to_bytes(2 + xt_handshake_dict_size, 4, 'big')
                                + int.to_bytes(20, 1, 'big')
                                + int.to_bytes(0, 1, 'big')
                                + xt_handshake_dict)
        peer_socket.sendall(xt_handshake_message)
        #xt_handshake_response: bytes = peer_socket.recv(1024)
        xt_handshake_response: bytes = get_peer_response(peer_socket)
        handshake_dict = decode_bencoded(xt_handshake_response[6:])
        if "m" not in handshake_dict or "ut_metadata" not in handshake_dict["m"]:
            raise Exception(f"Invalid extension handshake response! {handshake_dict} | {xt_handshake_response}")
    else:
        raise Exception("Peer does not support metadata extension!")
    handshake_dict["Peer ID"] = peer_response_id
    return peer_socket, handshake_dict

def get_magnet_info(meta_info: dict, ext_handshake_dict: dict, peer_socket: socket) -> dict:
    message_id = 20
    ext_message_id = ext_handshake_dict['m']['ut_metadata']
    payload_dict = {'msg_type': 0, 'piece': 0}
    message_payload = bencode_info_dict(payload_dict)
    request_message = (int.to_bytes(2 + len(message_payload), 4, 'big')
                       + int.to_bytes(message_id, 1, 'big')
                       + int.to_bytes(ext_message_id, 1, 'big') + message_payload)
    peer_socket.sendall(request_message)
    #magnet_info_response = peer_socket.recv(1024)
    magnet_info_response = get_peer_response(peer_socket)
    magnet_info_dict = decode_bencoded(magnet_info_response[6:])
    metadata_piece_size = magnet_info_dict['total_size']
    metadata_piece_dict = decode_bencoded(magnet_info_response[-metadata_piece_size:])
    magnet_info = {"Tracker URL": meta_info["Tracker URL"], "Length": metadata_piece_dict["length"],
                   "Info Hash": hashlib.sha1(magnet_info_response[-metadata_piece_size:]),
                   "Piece Length": metadata_piece_dict["piece length"]}
    piece_hashes = metadata_piece_dict["pieces"]
    piece_hashes_list = []
    for i in range(0, len(piece_hashes), 20):
        piece_hashes_list.append(piece_hashes[i:i + 20].hex())
    magnet_info["Piece Hashes"] = piece_hashes_list
    return magnet_info

def process_base_command(command: str) -> None:
    bencoded_value = get_bencoded(command)
    validate_bencoded(bencoded_value)
    if command == "decode":
        decoded_val = decode_bencoded(bencoded_value)
        print((json.dumps(decoded_val)))
    elif command == "info":
        meta_info: dict = get_meta_info(bencoded_value)
        print(f"Tracker URL: {meta_info['Tracker URL']}")
        print(f"Length: {meta_info['Length']}")
        print(f"Info Hash: {meta_info['Info Hash'].hexdigest()}")
        print(f"Piece Length: {meta_info['Piece Length']}")
        print("Piece Hashes: ")
        print("\n".join(meta_info["Piece Hashes"]))
    else:
        meta_info: dict = get_meta_info(bencoded_value)
        if command == "peers":
            peer_list: list = get_peer_list(meta_info)
            print("\n".join(peer_list))
        else:
            peer_list: list = get_peer_list(meta_info)
            peer_socket, handshake_response = perform_handshake(meta_info, peer_list)
            bitfield_message: bytes = get_peer_response(peer_socket)

            if command == "handshake":
                peer_response_id = handshake_response[-20:].hex()
                print(f"Peer ID: {peer_response_id}")
            elif command == "download_piece":
                piece_outfile = Path(sys.argv[3])
                piece_index = int(sys.argv[5])
                interested_message = (int.to_bytes(1, 4, 'big')
                                      + int.to_bytes(2, 1, 'big'))
                peer_socket.sendall(interested_message)
                unchoke_message: bytes = get_peer_response(peer_socket)
                piece_data: bytes = download_piece(meta_info, peer_socket, piece_index)
                piece_outfile.write_bytes(piece_data)
                print(f"piece downloaded to {piece_outfile}")
            elif command == "download":
                interested_message = (int.to_bytes(1, 4, 'big')
                                      + int.to_bytes(2, 1, 'big'))
                peer_socket.sendall(interested_message)
                unchoke_message: bytes = get_peer_response(peer_socket)
                download_file(meta_info, peer_socket)
                print("torrent file download completed.")
            peer_socket.close()

def process_magnet_command(command: str) -> None:
    if command in ("magnet_parse", "magnet_handshake", "magnet_info"):
        magnet_link = sys.argv[2]
    else:
        magnet_link = sys.argv[4]
    meta_info: dict = parse_magnet_link(magnet_link)
    if command == "magnet_parse":
        print(f"Tracker URL: {meta_info['Tracker URL']}")
        print(f"Info Hash: {meta_info['Info Hash']}")
    elif command == "magnet_handshake":
        peer_socket, ext_handshake_dict = perform_extension_handshake(meta_info)
        peer_socket.close()
        print(f"Peer ID: {ext_handshake_dict['Peer ID']}")
        print(f"Peer Metadata Extension ID: {ext_handshake_dict['m']['ut_metadata']}")
    else:
        peer_socket, ext_handshake_dict = perform_extension_handshake(meta_info)
        magnet_info: dict = get_magnet_info(meta_info, ext_handshake_dict, peer_socket)

        if command == "magnet_info":
            print(f"Tracker URL: {magnet_info['Tracker URL']}")
            print(f"Length: {magnet_info['Length']}")
            print(f"Info Hash: {magnet_info['Info Hash'].hexdigest()}")
            print(f"Piece Length: {magnet_info['Piece Length']}")
            print("Piece Hashes: ")
            print("\n".join(magnet_info["Piece Hashes"]))
        elif command == "magnet_download_piece":
            piece_outfile = Path(sys.argv[3])
            piece_index = int(sys.argv[5])
            interested_message = (int.to_bytes(1, 4, 'big')
                                  + int.to_bytes(2, 1, 'big'))
            peer_socket.sendall(interested_message)
            unchoke_message: bytes = get_peer_response(peer_socket)
            magnet_piece_data: bytes = download_piece(magnet_info, peer_socket, piece_index)
            piece_outfile.write_bytes(magnet_piece_data)
            print(f"magnet piece downloaded to {piece_outfile}")
        elif command == "magnet_download":
            interested_message = (int.to_bytes(1, 4, 'big')
                                  + int.to_bytes(2, 1, 'big'))
            peer_socket.sendall(interested_message)
            unchoke_message: bytes = get_peer_response(peer_socket)
            download_file(magnet_info, peer_socket)
            print("torrent magnet file download completed.")
        peer_socket.close()

def get_peer_response(peer_socket: socket) -> bytes:
    peer_response_length_header = peer_socket.recv(4)
    response_size = int.from_bytes(peer_response_length_header, 'big')
    peer_response = peer_response_length_header + peer_socket.recv(response_size)
    return peer_response

def main():
    command = sys.argv[1]
    base_commands = {"decode", "info", "peers", "handshake", "download_piece", "download"}
    magnet_commands = {"magnet_parse", "magnet_handshake", "magnet_info", "magnet_download_piece", "magnet_download"}

    if command in base_commands:
        process_base_command(command)
    elif command in magnet_commands:
        process_magnet_command(command)
    else:
        raise Exception("Invalid command!")


if __name__ == "__main__":
    peer_id = '00112233445566998877'
    main()
