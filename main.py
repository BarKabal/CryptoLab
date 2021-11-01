# Bartosz Kabała 307375

# Zad.1
# Napisz skrypt łamiący metodą brutalnej siły kryptogram zaszyfrowany RC4 z trzyznakowym hasłem.
# Załóż, że odszyfrowujemy tekst. Spróbuj złamać klucze crypto.rc4 i crypto2.rc4.

# Zad.2
# Napisz skrypt szyfrujący szyfrem przesuwającym o n-znaków tekst złożony z dużych i małych liter.
# Porównaj histogramy dla tekstu wejściowego i kryptogramu.
# Warto przeanalizować różne języki tekstu wejściowego.

import string
from math import log2
import numpy as np
from Crypto.Cipher import ARC4
import matplotlib.pyplot as plt


def count_raw_bytes(text):
    count = np.zeros(256)
    for c in text:
        if c < 256:
            count[c] += 1
    return count


def count_letters(text):
    count = np.zeros(26)
    text = text.lower()
    for i, letter in enumerate(string.ascii_lowercase):
        count[i] = text.count(letter)
    return count


def entropy(text):
    count = count_raw_bytes(text)
    prob = count / len(text)
    H = 0.0
    for i in range(256):
        if prob[i] > 0.0:
            H -= prob[i] * log2(prob[i])
    return H


def brute_force(encrypted_text, entropy_bound):
    k = ['?', '?', '?']
    for k[0] in string.ascii_lowercase:
        for k[1] in string.ascii_lowercase:
            for k[2] in string.ascii_lowercase:
                key = ''.join(k)
                decrypter = ARC4.new(key.encode('utf-8'))
                decrypted_text = decrypter.decrypt(encrypted_text)
                H = entropy(decrypted_text)
                if H < entropy_bound:
                    print("Klucz: " + key)
                    print("Wiadomość: " + str(decrypted_text))
                    return
    print("Nie znaleziono poprawnego klucza")


def move_text_by_letter(s, n):
    n = n % 26
    bytes_in_text = [ord(c) for c in s]
    big_letters = range(65, 91)
    small_letters = range(97, 123)
    for index, b in enumerate(bytes_in_text):
        if b in big_letters:
            move_byte(bytes_in_text, b, index, n, big_letters.stop)
        elif b in small_letters:
            move_byte(bytes_in_text, b, index, n, small_letters.stop)
    moved_string = ''.join(chr(byte) for byte in bytes_in_text)
    return moved_string


def move_byte(bytes_in_text, b, index, n, upper_bound):
    if b + n < upper_bound:
        bytes_in_text[index] = b + n
    else:
        bytes_in_text[index] = b + n - 26


def plot_exc2(letters_in_text, letters_in_encrypted_text, title):
    lowercase_letters = string.ascii_lowercase
    plt.subplot()
    plt.bar(np.arange(len(lowercase_letters)) - 0.2, letters_in_text, width=0.4)
    plt.bar(np.arange(len(lowercase_letters)) - 0.2, letters_in_encrypted_text, width=0.4)
    plt.xticks(np.arange(len(lowercase_letters)), lowercase_letters)
    plt.title(title)
    plt.ylabel('Ilość')
    plt.legend(labels=['Tekst przed szyfrowaniem', 'Tekst po szyfrowaniu'])
    plt.show()


def main():
    entry_bound = 6.0
    ARC4.key_size = range(3, 257)
    letter_shift = 10
    print("Wczytywanie plików...")
    encrypted_text1 = open("crypto.rc4", "rb").read()  # b for binary mode
    encrypted_text2 = open("crypto2.rc4", "rb").read()  # b for binary mode
    pl_text = open("sample_PL.txt", "r", encoding='utf-8').read()
    eng_text = open("sample_ENG.txt", "r", encoding='utf-8').read()
    fr_text = open("sample_FR.txt", "r", encoding='utf-8').read()
    print("Zadanie 1: Bruteforce")
    brute_force(encrypted_text1, entry_bound)   # def
    brute_force(encrypted_text2, entry_bound)   # eac
    print("Zadanie 2:")
    plot_exc2(count_letters(pl_text), count_letters(move_text_by_letter(pl_text, letter_shift)), "Polski")
    plot_exc2(count_letters(eng_text), count_letters(move_text_by_letter(eng_text, letter_shift)), "Angielski")
    plot_exc2(count_letters(fr_text), count_letters(move_text_by_letter(fr_text, letter_shift)), "Francuski")

if __name__ == "__main__":
    main()


# Wnioski
# Kluczem do crypto.rc4 jest def, zaś do crypto2.rc4 eac.
# Na wykresach widać przesunięcie o 10 liter.
# W języku polskim najczęściej występuje litera a, w angielskim i francuskim litera e.
