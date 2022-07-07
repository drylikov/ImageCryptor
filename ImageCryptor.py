# -*- coding: utf-8 -*-
#
#  ImageCryptor
#  Created by LulzLol231 at 08/02/2021
#
import os
import sys
import time
import logging
import hashlib
import secrets
from typing import Optional, Union
from base64 import b64decode, b64encode

from Crypto import Random
from Crypto.Cipher import AES


MAIN_KEY = 'U1RVUElEX1VTRVJTX01VU1RfRElF'
DEBUG = False
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='[%(levelname)s] %(name)s (%(lineno)d) >> %(message)s')


def getLogger(module_name: str, func_name: str) -> logging.Logger:
    '''Returns Logger instance with module::func name.

    Args:
        module_name (str): module name.
        func_name (str): function name.

    Returns:
        logging.Logger: Logger instance.
    '''
    return logging.getLogger(f'{module_name}::{func_name}')


class AESCipher(object):
    '''AESCipher class.
    Encypting & decrypting using AES-256.

    Args:
        key (str): key for encrypting.

    Example:
        >>> aes = AESCipher('somekey')
        >>> aes.encrypt('hello world')  # output: $encrypted text$
        >>> aes.decyrpt('$encrypted text$')  # output: "hello world"
    '''

    def __init__(self, key: str):
        self.block_size = AES.block_size
        self.clear_key = key
        self.key = hashlib.sha256(b64encode(key.encode())).digest()
        self.log = getLogger('ImageCryptor', 'AESCipher')
        self.log.debug(f'Initiated with key: {key}')

    def encrypt(self, plain_text: str) -> str:
        '''Returns encrypted with AES-256 text.

        Args:
            plain_text (str): text for encrypting.

        Returns:
            str: encrypted text.
        '''
        if plain_text:
            plain_text = self.__pad(plain_text)
            iv = Random.new().read(self.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            encrypted_text = cipher.encrypt(plain_text.encode())
            return b64encode(iv + encrypted_text).decode("utf-8")
        else:
            self.log.error('Trying encrypt data without data.')
            return ''

    def decrypt(self, encrypted_text: str) -> Optional[Union[str, None]]:
        '''Returns decrypted with AES-256 plain text.

        Args:
            encrypted_text (str): encrypted with AES-256 text.

        Returns:
            Optional[Union[str, None]]: plain text or None if key is wrong.
        '''
        try:
            encrypted_text = b64decode(encrypted_text)
        except Exception as e:
            self.log.error(
                f'Error while trying base64 decode encrypted text: {str(e)}')
            return None
        else:
            if encrypted_text:
                iv = encrypted_text[:self.block_size]
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                try:
                    plain_text = cipher.decrypt(
                        encrypted_text[self.block_size:])
                    unpadded = self.__unpad(plain_text)
                except Exception as e:
                    self.log.error(
                        f'Error while trying decrypt text with key ({self.clear_key}): {str(e)}')
                    return None
                else:
                    try:
                        result = unpadded.decode()
                    except Exception as e:
                        self.log.debug(
                            f'Error while trying decode decrypted text: {str(e)}')
                        return None
                    else:
                        return result
            else:
                self.log.error('Trying decrypt data without data.')
                return None

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - \
            len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]


class Crypto:
    def __init__(self) -> None:
        self.log = getLogger('ImageCryptor', 'Crypto')
        self.log.info('Initialized.')

    def checkEncFile(self, path: str) -> bool:
        '''Checks if file by path is encrypted with ImageCryptor file.

        Args:
            path (str): path for encrypted file.

        Returns:
            bool: True or False.
        '''
        if os.path.exists(path):
            data = None
            with open(path, 'rb') as f:
                data = f.read(6)
            try:
                data = data.decode()
            except Exception as e:
                self.log.warning(f'"checkEncFile": Can\'t decode file header: {str(e)}')
                return False
            else:
                self.log.debug(f'"checkEncFile": File header: {data}')
                return data == 'ENCWIC'

    def getRandomKey(self) -> str:
        '''Returns random key for encrypting.

        Returns:
            str: random key.
        '''
        return b64encode(Random.get_random_bytes(30)).decode()

    def encryptFile(self, path: str) -> None:
        '''Encrypts image with random key.

        Args:
            path (str): full path to file.
        '''
        if os.path.exists(path):
            data = None
            with open(path, 'rb') as f:
                data = f.read()
            if DEBUG is False:
                print(str(data))
            b_data = b64encode(data).decode()
            if DEBUG is False:
                print(b_data)
            key = self.getRandomKey()
            self.log.debug(f'"encryptFile": Generated key: {key}')
            enc = AESCipher(key)
            enc_data = enc.encrypt(b_data)
            if DEBUG is False:
                print(enc_data)
            file_name = f'Temp{str(secrets.randbits(20))}'
            self.log.debug(f'"encryptFile": Generated filename: {file_name}')
            header = 'ENCWIC::'
            enc = AESCipher(MAIN_KEY)
            enc_key = enc.encrypt(key)
            if DEBUG is False:
                print(enc_key)
            header += enc_key + '::'
            header += enc_data + '::'
            header += b64encode(path.split(os.path.sep)[::-1][0].split('.')[::-1][0].encode()).decode()
            with open(file_name, 'w') as f:
                f.write(header)
            os.remove(path)

    def decryptFile(self, path: str) -> None:
        '''Decrypt image.

        Args:
            path (str): full path to encrypted file.
        '''
        if os.path.exists(path):
            data = None
            with open(path, 'rb') as f:
                data = f.read()
            try:
                data = data.decode()
            except Exception as e:
                self.log.error(f'"decryptFile": Can\'t decode data from file: {str(e)}')
            else:
                if DEBUG is False:
                    print(data)
                enc_file = data.split('::')
                if len(enc_file) != 4:
                    self.log.error('"decryptFile": Corrupted encrypted file!')
                else:
                    enc_key = enc_file[1]
                    enc_data = enc_file[2]
                    enc_ext = enc_file[3]
                    if DEBUG is False:
                        print(enc_key)
                    enc = AESCipher(MAIN_KEY)
                    dec_key = enc.decrypt(enc_key)
                    if DEBUG is False:
                        print(dec_key)
                    if dec_key:
                        if DEBUG is False:
                            print(enc_data)
                        enc = AESCipher(dec_key)
                        dec_data = enc.decrypt(enc_data)
                        if DEBUG is False:
                            print(dec_data)
                        if dec_data:
                            try:
                                dec_data = b64decode(dec_data.encode())
                            except Exception as e:
                                self.log.error(f'"decryptFile": Can\'t decode decrypted data!')
                            else:
                                if DEBUG is False:
                                    print(str(dec_data))
                                dec_ext = b64decode(enc_ext.encode()).decode()
                                if DEBUG is False:
                                    print(dec_ext)
                                filename = path.split(os.path.sep)[::-1][0] + '.' +dec_ext
                                with open(filename, 'wb') as f:
                                    f.write(dec_data)
                                os.startfile(filename)
                                time.sleep(1)
                                if DEBUG is False:
                                    os.remove(filename)


if DEBUG and 'ENCWIC_FILE' in os.environ:
    Crypto().decryptFile(os.environ.get('ENCWIC_FILE'))


if DEBUG and 'ENCWIC_ENCFILE' in os.environ:
    Crypto().encryptFile(os.environ.get('ENCWIC_ENCFILE'))

if __name__ == '__main__':
    if len(sys.argv) > 1:
        crypto = Crypto()
        if crypto.checkEncFile(sys.argv[1]):
            crypto.decryptFile(sys.argv[1])
            if DEBUG:
                input('Press "ENTER" for exit.')
        else:
            crypto.encryptFile(sys.argv[1])
            if DEBUG:
                input('Press "ENTER" for exit.')
    else:
        print('No file found in args.')
        if DEBUG:
            input('Press "ENTER" for exit.')
