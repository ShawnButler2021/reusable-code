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

class FeistelNetwork:
    def __init__(self):
        self.__keys = []
        self.__round = default_round_function

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

    def set_round_function(self,func):
        self.__round = func

    def encrypt(self, msg):
        # checking if message has been assigned
        if msg == '':
            raise EmptyMessageError

        # adding an invisible character if the length of the key is odd
        if len(msg) % 2 != 0:
            msg += ' '

        left, right = msg[:len(msg) // 2], msg[len(msg) // 2:]


        # running rounds
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




