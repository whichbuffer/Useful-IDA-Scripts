import idaapi

# XORDecryptor Script
# This script decrypts data encrypted with XOR at a specific address in IDA Pro
# and adds a comment with the decrypted text in the disassembly.

def xor_decrypt(data, key):
    """Decrypts data using XOR with the given key."""
    return bytearray([b ^ key for b in data])

def find_length_of_data(address, termination_byte=0x00):
    """Finds the length of the data ending with a termination byte."""
    length = 0
    while True:
        byte = idaapi.get_byte(address + length)
        if byte == termination_byte:
            break
        length += 1
    return length

def decrypt_data_at_address(address, key):
    """Decrypts data at the given address and adds a comment in the assembly."""
    length = find_length_of_data(address)
    encrypted_data = idaapi.get_bytes(address, length)
    if not encrypted_data:
        print("Failed to read data")
        return

    decrypted_data = xor_decrypt(encrypted_data, key)
    decrypted_string = ''.join(map(chr, decrypted_data))
    idaapi.set_cmt(address, "Decrypted data: " + decrypted_string, False)
    print("Decrypted Data:", decrypted_data)

# Example usage
address = 0x1001D988  # The address where the encrypted data starts
key = 0x55  # The XOR key
decrypt_data_at_address(address, key)
