def bytearray_to_bitarray(m: bytes):
    bits = [0] * (len(m) * 8)
    for i in range(len(m)):
        num = m[i]
        for j in range(8):
            bits[i*8 + j] = num & 1
            num = num >> 1
    return bits
