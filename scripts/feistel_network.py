import math
import random
import string
import hashlib
from abc import ABC, abstractmethod




class BadFileError(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __str__(self):
        return f"{self.args[0]}"
class EmptyMessageError(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __str__(self):
        return f"{self.args[0]}"
class BadHashError(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __str__(self):
        return f"{self.args[0]}"
class BadKeyError(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __str__(self):
        return f"{self.args[0]}"
class BadRoundCountError(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __str__(self):
        return f"{self.args[0]}"


class FeistelNetwork:
    def __init__(self):
        self.__keys = []
        self.__round = default_round_function
        self.__round_count = 2

    def generate_keys(self, key_length, num):
        # make keys more difficult
        # currently round number (chr(i))
        key_list = []
        for i in range(0,num):
            temp = [random.choice(string.ascii_letters + string.digits + string.punctuation + string.whitespace) for i in range(1, key_length + 1)]
            temp = ''.join(temp)
            key_list.append(temp)
        self.__keys = key_list

    def __xor_strings(self, string1, string2):
        # input validation
        if type(string1) != str or type(string2) != str:
            raise TypeError('Parameters aren\'t strings.')
        # xoring characters in string individually (using ^)
        # and combining with list comprehension & join
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(string1, string2))

    def set_keys(self, key_list):
        if type(key_list) != list:
            raise BadKeyError('New keys must be a list.')
        for item in key_list:
            if type(item) != str:
                raise BadKeyError('All items in the new key list must be a string.')

        self.__keys = key_list

    def set_round_function(self, func):
        self.__round = func

    def set_round_count(self, num):
        if num < 2:
            raise BadRoundCountError('The number of rounds must be 2 or greater.')
        self.__round_count = num

    def encrypt(self, msg):
        # checking if message has been assigned
        if msg == '':
            raise EmptyMessageError

        # adding an invisible character if the length of the key is odd
        if len(msg) % 2 != 0:
            msg += ' '

        left, right = msg[:len(msg) // 2], msg[len(msg) // 2:]


        # running rounds
        for i in range(0, self.__round_count):
            for key in self.__keys:
                new_right = self.__xor_strings(left, self.__round(right, key))
                left = right
                right = new_right

        # assigning message
        msg = left + right

        return msg

    def decrypt(self, msg):
        # checking if message has been assigned
        if msg == '':
            raise EmptyMessageError


        # splitting message
        left, right = msg[:len(msg) // 2], msg[len(msg) // 2:]


        # running rounds in reverse
        for i in range(0,self.__round_count):
            for key in reversed(self.__keys):
                new_left = self.__xor_strings(right, self.__round(left, key))
                right = left
                left = new_left

        # assigning result, removing invisible character is present
        msg = (left+right)
        if (left+right)[-1] == ' ':
            msg = (left+right)[:-1]

        return msg

    def get_keys(self):
        return self.__keys

    def get_round_count(self):
        return self.__round_count


# new round functions must RETURN their final data
# data must be string
def default_round_function(data, key):
    # input validation
    if type(data) != str or type(key) != str:
        raise TypeError('Parameters aren\'t strings.')
    # keeping as string to work with __xor_strings
    # could have used .digest otherwise
    # data = hashlib.sha512(data.encode()).hexdigest()
    hash_obj = hashlib.new('SHA512')
    hash_obj.update(data.encode())

    return hash_obj.hexdigest()


# for testing purposes
# you should never call this module directly
if __name__ == '__main__':
    net = FeistelNetwork()
    net.generate_keys(5, 1)

    msg = input('Give a message: ')

    encrypted_msg = net.encrypt(msg)
    print(f'Encrypted: {encrypted_msg}')

    decrypted_msg = net.decrypt(encrypted_msg)
    print(f'Decrypted: {decrypted_msg}')



