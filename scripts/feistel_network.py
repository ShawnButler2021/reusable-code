import math
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


class FeistelNetwork:
    def __init__(self):
        self.__keys = []
        self.__message = ''
        self.__message_length = -1

        self.__round = -1

    def __generate_keys(self):
        # making a string key
        if self.__message == '':
            print('Message is empty. Please assign a message and try again')
            return
        self.__message_length = len(self.__message) // 2
        self.__keys = [chr(i) * self.__message_length for i in range(1, self.__rounds_num + 1)]

    def xor_strings(self, string1, string2):
        # input validation
        if type(string1) != str or type(string2) != str:
            raise TypeError('Parameters aren\'t strings.')
        # xoring characters in string individually (using ^)
        # and combining with list comprehension & join
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(string1, string2))

    def set_round_function(self,func):
        self.__round = func

    def encrypt(self, rounds):
        # input validation
        if type(rounds) != int:
            raise TypeError('Parameters aren\'t integers.')
        # checking if message has been assigned
        if self.__message == '':
            raise EmptyMessageError

        # adding an invisible character if the length of the key is odd
        if len(self.__message) % 2 != 0:
            self.__message += ' '
        self.__rounds_num = rounds

        left, right = self.__message[:len(self.__message) // 2], self.__message[len(self.__message) // 2:]
        self.__generate_keys()

        # running rounds
        for key in self.__keys:
            new_right = self.xor_strings(left, self.__round(self, right, key))
            left = right
            right = new_right

        # assigning message
        self.__message = left + right

    def decrypt(self):
        # checking if message has been assigned
        if self.__message == '':
            raise EmptyMessageError


        # splitting message
        left, right = self.__message[:len(self.__message) // 2], self.__message[len(self.__message) // 2:]
        self.__generate_keys()

        # running rounds in reverse
        for key in reversed(self.__keys):
            new_left = self.xor_strings(right, self.__round(self, left, key))
            right = left
            left = new_left

        # assigning result, removing invisible character is present
        self.__message = (left+right)
        if (left+right)[-1] == ' ':
            self.__message = (left+right)[:-1]

    def set_message(self, message):
        self.__message = message

    def get_message(self):
        return self.__message

    def set_keys(self, key_list):
        if type(key_list != list):
            # add failure message here
            return
        self.__keys = key_list

    def get_keys(self):
        return self.__keys

def temp_function(obj, data, key):
    # input validation
    if type(data) != str or type(key) != str:
        raise TypeError('Parameters aren\'t strings.')
    # keeping as string to work with xor_strings
    # could have used .digest otherwise
    # data = hashlib.sha512(data.encode()).hexdigest()
    hash_obj = hashlib.new('SHA512')
    hash_obj.update(data.encode())

    return obj.xor_strings(hash_obj.hexdigest(), key)

if __name__ == '__main__':
    net = FeistelNetwork()
    x = input('Give message: ')

    net.set_message(x)
    net.set_round_function(temp_function)

    print(f'Message: {net.get_message()}')

    net.encrypt(5)
    print(f'Encrypted: {net.get_message()}')
    net.decrypt()
    print(f'Decrypted: {net.get_message()}')


