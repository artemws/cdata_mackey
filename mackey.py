#!/usr/bin/env python3
"""
Использование: python mackey.py XX:XX:XX:XX:XX:XX
"""

import struct
import sys

# ----------------------------------------------------------------------
# Точная реализация SHA1 из прошивки (с нестандартными начальными значениями)
def rotl(n, x):
    """Циклический сдвиг влево 32-битного числа на n бит."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def ft(t, b, c, d):
    """Функция ft для SHA1."""
    if t < 20:
        return (b & c) | ((~b) & d)
    elif t < 40:
        return b ^ c ^ d
    elif t < 60:
        return (b & c) | (b & d) | (c & d)
    else:
        return b ^ c ^ d

def k(t):
    """Константы K для SHA1."""
    if t < 20:
        return 0x5A827999
    elif t < 40:
        return 0x6ED9EBA1
    elif t < 60:
        return 0x8F1BBCDC
    else:
        return 0xCA62C1D6

def sha1_firmware(data):
    """
    Кастомный SHA1, используемый в прошивке.
    data: bytes
    Возвращает 20 байт хэша (big-endian).
    """
    ml = len(data) * 8
    # Добавляем бит 0x80
    data += b'\x80'
    # Добавляем нули, пока не останется 4 байта до конца блока 64 байта
    while (len(data) + 4) % 64 != 0:
        data += b'\x00'
    # Добавляем длину как 4 байта big-endian
    data += ml.to_bytes(4, byteorder='big')

    # Начальные значения (отличаются от стандартных)
    h0 = 0x67452301
    h1 = 0x10325476
    h2 = 0x98BADCFE
    h3 = 0xC3D2E1F0
    h4 = 0xEFCDAB89

    # Обрабатываем блоки по 64 байта
    for i in range(0, len(data), 64):
        block = data[i:i+64]
        w = [0] * 80
        for t in range(16):
            w[t] = struct.unpack('>I', block[t*4:t*4+4])[0]
        for t in range(16, 80):
            w[t] = rotl(1, w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16])

        a, b, c, d, e = h0, h1, h2, h3, h4
        for t in range(80):
            f = ft(t, b, c, d)
            temp = (rotl(5, a) + f + e + k(t) + w[t]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotl(30, b)
            b = a
            a = temp
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return struct.pack('>5I', h0, h1, h2, h3, h4)

def hmac_sha1_firmware(key, data):
    """
    HMAC-SHA1 с использованием кастомного SHA1.
    key, data: bytes
    Возвращает 20 байт HMAC.
    """
    block_size = 64
    if len(key) > block_size:
        key = sha1_firmware(key)
    if len(key) < block_size:
        key += b'\x00' * (block_size - len(key))

    o_key_pad = bytes([x ^ 0x5C for x in key])
    i_key_pad = bytes([x ^ 0x36 for x in key])

    inner = sha1_firmware(i_key_pad + data)
    outer = sha1_firmware(o_key_pad + inner)
    return outer

def compute_mackey(mac_str):
    """
    Основная функция: принимает MAC в формате XX:XX:XX:XX:XX:XX,
    возвращает строку MacKey (32 hex-символа).
    """
    # Удаляем разделители и преобразуем в байты
    mac_clean = mac_str.replace(':', '').replace('-', '').replace(' ', '')
    if len(mac_clean) != 12:
        raise ValueError("Неверный формат MAC. Ожидается 6 групп по 2 hex-цифры.")
    mac_bytes = bytes.fromhex(mac_clean)

    # Константы из прошивки
    const_bytes = bytes.fromhex("356B8BD3")   # DAT_00054ea4
    param1_bytes = bytes.fromhex("04000101")  # 0x04000101 (big-endian)

    # Формируем 24-байтовый ключ XOR
    key = bytearray()
    for i in range(4):
        for j in range(6):
            key.append(const_bytes[i] ^ param1_bytes[i] ^ mac_bytes[j])

    # Вычисляем HMAC-SHA1
    hmac_result = hmac_sha1_firmware(bytes(key), mac_bytes)

    # Берём первые 16 байт и возвращаем hex
    return hmac_result[:16].hex()

# ----------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python mackey_gen.py MAC")
        print("Пример: python mackey_gen.py 80:F7:A6:18:B7:AA")
        sys.exit(1)

    mac_input = sys.argv[1]
    try:
        mackey = compute_mackey(mac_input)
        print(mackey)
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
