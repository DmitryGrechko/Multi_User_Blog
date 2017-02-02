class rot13:

    def __init__(self):
        pass

alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']


def rot(letter):
    if ord(letter) >= 110:
        return chr(-13 + ord(letter))
    elif ord(letter) < 84:
        return chr(39 + ord(letter))
    return chr(ord(letter) + 13)


def conv(word):
    n = ''
    for letter in word:
        if letter.isupper():
            n += (rot(letter.lower()).capitalize())
        elif letter in alphabet:
            n += rot(letter)
        else:
            n += letter
    return n
