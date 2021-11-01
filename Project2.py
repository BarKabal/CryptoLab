import string
import imghdr
from PIL import Image
from Crypto.Cipher import AES


def null_padding(data, length=16):
    return data + b"\x00" * (length - len(data) % length)


def convert_to_RGB(data):
    pixels = []

    for i in range(0, len(data) - 1, 3):
        r = int(data[i])
        g = int(data[i + 1])
        b = int(data[i + 2])

        pixels.append((r, g, b))
    return pixels


def decrypt_full(input_filenames, key, mode, iv=None):
    img_in = open(input_filenames, "rb")
    data = img_in.read()
    padded_data = null_padding(data)
    decrypter = AES.new(key, mode)
    decrypted_data = decrypter.decrypt(padded_data)
    decrypted_data_string = str(decrypted_data)
    img_in.close()
    if decrypted_data_string[2:4] == "BM":
        img_out = open("security_ECB_decrypted.bmp", "wb")
        decrypted_data_unpadded = decrypted_data[:len(data)]
        img_out.write(decrypted_data_unpadded)
        img_out.close()
        return 1



def main():
    input_filename = "security_ECB_encrypted.bmp"
    input_filename2 = "security_CBC_encrypted.bmp"
    right_key = ''
    for i in string.ascii_lowercase + string.digits:
        key = ''.join(i * 16)
        if decrypt_full(input_filename, key.encode('utf-8'), AES.MODE_ECB):
            print("Klucz: " + key)
            right_key = key
            break
    if right_key == '':
        print("Nie znaleziono poprawnego klucza")
    else:
        decrypt_full(input_filename2, right_key.encode('utf-8'), AES.MODE_CBC)


if __name__ == '__main__':
    main()
