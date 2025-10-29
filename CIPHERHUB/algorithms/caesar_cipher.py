def caesar_encrypt(text, key):
    result = ''
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            result += chr((ord(char) + key - shift) % 26 + shift)
        else:
            result += char
    return result

def caesar_decrypt(text, key):
    result = ''
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            result += chr((ord(char) - key - shift) % 26 + shift)
        else:
            result += char
    return result
