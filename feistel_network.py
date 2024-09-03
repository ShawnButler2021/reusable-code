import math
import hashlib



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
    # Data series
    def __init__(self):
        # information area
        self.__hash_alg_name = 'sha512'
        self.__rounds_num = -1

        # data area
        self.__keys = []
        self.__message = ''
        self.__message_length = -1
    def __str__(self):
        string = f'Feistel Network\n'
        string += f'* Key rounds: {self.__rounds_num}\n'
        string += f'* Key length: {self.__message_length}\n'
        string += f'* Hash algorithm: {self.__hash_alg_name}'

        return string


    # Feistel series
    # private
    def __generate_keys(self):
        # making a string key
        if self.__message == '':
            print('Message is empty. Please assign a message and try again')
            return
        self.__message_length = len(self.__message) // 2
        self.__keys = [chr(i) * self.__message_length for i in range(1, self.__rounds_num + 1)]
    def __xor_strings(self, string1, string2):
        # input validation
        if type(string1) != str or type(string2) != str:
            raise TypeError('Parameters aren\'t strings.')
        # xoring characters in string individually (using ^)
        # and combining with list comprehension & join
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(string1, string2))
    def __round(self, data, key):
        # input validation
        if type(data) != str or type(key) != str:
            raise TypeError('Parameters aren\'t strings.')
        # keeping as string to work with xor_strings
        # could have used .digest otherwise
        #data = hashlib.sha512(data.encode()).hexdigest()
        hash_obj = hashlib.new(self.__hash_alg_name)
        hash_obj.update(data.encode())

        return self.__xor_strings(hash_obj.hexdigest(), key)
    # public
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
            new_right = self.__xor_strings(left, self.__round(right, key))
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
            new_left = self.__xor_strings(right, self.__round(left, key))
            right = left
            left = new_left

        # assigning result, removing invisible character is present
        self.__message = (left+right)
        if (left+right)[-1] == ' ':
            self.__message = (left+right)[:-1]


    # Management
    # public
    def set_hash(self, hash_name):
        whitelist = [
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512'
        ]

        if hash_name in whitelist:
            self.__hash_alg_name = hash_name
        else:
            raise BadHashError('Given hash name isn\'t in list')
    def set_message(self, message):
        # input validation
        if type(message) != str:
            raise TypeError('Message isn\'t a string.')
        self.__message = message
    def get_message(self):
        return self.__message
    def keys_to_file(self, filename):
        # input validation
        if type(filename) != string:
            raise TypeError('Filename is not a string.')
        if (filename == 'main.py' or filename == 'feistel_network.py'):
            raise BadFileError('Cannot use that filename')

        results = ''
        for key in self.__keys:
            results += key + ','

        with open(filename, 'w') as f:
            f.write(results[:-1])
    def message_to_file(self, filename):
        # input validation
        if type(filename) != string:
            raise TypeError('Filename is not a string.')
        if (filename == 'main.py' or filename == 'feistel_network.py'):
            raise BadFileError('Cannot use that filename')

        with open(filename, 'w') as f:
            f.write(self.__message)
    def file_to_keys(self,filename):
        # input validation
        if type(filename) != string:
            raise TypeError('Filename is not a string.')
        if (filename == 'main.py' or filename == 'feistel_network.py'):
            raise BadFileError('Cannot use that filename')
        # FileNotFoundError may be called here

        results = None
        with open(filename, 'r') as f:
            self.__keys = list(f.read().split(','))
    def file_to_msg(self,filename):
        # input validation
        if type(filename) != string:
            raise TypeError('Filename is not a string.')
        if (filename == 'main.py' or filename == 'feistel_network.py'):
            raise BadFileError('Cannot use that filename')
        # FileNotFoundError may be called here

        results = None
        with open(filename, 'r') as f:
            self.__message = list(f.read())


if __name__ == '__main__':
    net = FeistelNetwork()

    x = input('Give message: ')

    net.set_message(x)

    print(f'Message: {net.get_message()}')


    net.encrypt(5)
    print(f'Encrypted: {net.get_message()}')
    net.decrypt()
    print(f'Decrypted: {net.get_message()}')


