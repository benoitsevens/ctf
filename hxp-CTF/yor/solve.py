from collections import Counter
import sys

from Crypto.Util.number import long_to_bytes
from pwn import remote, context


DUMMY_KEY = bytes([0] * 16)

greets = [
        "Herzlich willkommen! Der Schlüssel ist {0}, und die Flagge lautet {1}.",
        "Bienvenue! Le clé est {0}, et le drapeau est {1}.",
        "Hartelĳk welkom! De sleutel is {0}, en de vlag luidt {1}.",
        "ようこそ！鍵は{0}、旗は{1}です。",
        "歡迎！鑰匙是{0}，旗幟是{1}。",
        "Witamy! Niestety nie mówię po polsku...",
    ]

def get_ct(length=None):
    while True:
        r = remote(sys.argv[1], int(sys.argv[2]))
        ct = bytes.fromhex(r.recvline().decode())
        r.close()
        if length and len(ct) == length or not length:
            return ct


def get_flag_length():
    lengths = {}

    while len(lengths.keys()) != len(greets):
        ct = get_ct()
        lengths[len(ct)] = ct

    max_length = max(lengths.keys())

    greet_without_flag = greets[0].format(DUMMY_KEY.hex(), "").encode()

    flag_length = max_length - len(greet_without_flag)
    print("[*] Flag length:", flag_length)

    return flag_length

def get_flag(flag_length, flag, greets_index):
    dummy_flag = '0' * flag_length
    greet = greets[greets_index].format(DUMMY_KEY.hex(), dummy_flag).encode()

    ct = get_ct(length=len(greet))
    assert len(greet) == len(ct)

    key = ['?'] * 16 * 8
    for i, b in enumerate(greet):
        if b == 0x30:
            continue
        for bit_offset in range(0, 8):
            pt_bit = (b >> (7-bit_offset)) & 1
            ct_bit = (ct[i] >> (7-bit_offset)) & 1
            if not pt_bit and not ct_bit:
                assert key[(i * 8 + bit_offset) % len(key)] != '1'
                key[(i * 8 + bit_offset) % len(key)] = '0'
            elif not pt_bit and ct_bit:
                assert key[(i * 8 + bit_offset) % len(key)] != '0'
                key[(i * 8 + bit_offset) % len(key)] = '1'

    greet = greets[greets_index].format(DUMMY_KEY.hex(), dummy_flag).encode()

    flag_offset = greet.find(dummy_flag.encode())
    for i in range(flag_length):
        for bit_offset in range(0, 8):
            ct_bit = (ct[flag_offset + i] >> (7 - bit_offset)) & 1
            key_bit = key[((flag_offset + i)*8 + bit_offset) % len(key)]
            if key_bit == '?':
                continue
            else:
                key_bit = int(key_bit)
            if not key_bit and not ct_bit:
                assert flag[i*8 + bit_offset] != '1'
                flag[i*8 + bit_offset] = '0'
            elif not key_bit and ct_bit:
                assert flag[i*8 + bit_offset] != '0'
                flag[i*8 + bit_offset] = '1'
        
    return flag

context.log_level = 'error'

flag_length = get_flag_length()

flag = ['?'] * flag_length * 8
while '?' in flag:
    for greet_index in range(5):
        flag = get_flag(flag_length, flag, greet_index)
        print("[*] Remaining unknown bits:", flag.count('?'))

print("[*] Flag:", long_to_bytes(int("".join(flag), 2)))
