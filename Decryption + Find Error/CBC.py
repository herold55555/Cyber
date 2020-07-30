# Herold , Tahar, 342611274
# Python 3.6

from Crypto.Cipher import AES

"""
In this function we use the library AES for decrypting just one block,
we begin by separate the cipher text into different blocks, and than we pass over all blocks
with a loop and doing XOR between the cipher text and the block before
In the end we reverse the order and return the plain text
"""


def cbc_custom_decrypt(k, n, cipher):
    if n <= 0:
        return
    my_IV = cipher[:16]
    my_blocks = []
    crypto = AES.new(k, AES.MODE_ECB)
    #add the first block that is not the IV
    my_blocks.append(cipher[16:32])
    my_decryption = []
    my_result = []
    # loop to separate the text into blocks
    if n > 1:
        for i in range(2, n + 1):
            index = 16 * i
            my_blocks.append(cipher[index: index + 16])
    blocks_number = len(my_blocks)
    # loop that make the decryption block by block
    for j in range(1, blocks_number):
        decryption = crypto.decrypt(my_blocks[blocks_number - j])
        one_slice = XOR(decryption, my_blocks[blocks_number - j - 1])
        my_decryption.append(one_slice)
    # last decryption is the first part of the plaintext
    last_decryption = crypto.decrypt(my_blocks[0])
    first_slice = XOR(last_decryption, my_IV)
    my_decryption.append(first_slice)
    my_length = len(my_decryption)
    # loop to put all the plaintext together and in the right order
    for k in range(2, my_length + 1):
        first_slice.extend(my_decryption[my_length - k])
    return bytes(first_slice)

"""
In this function we begin by finding the block bi + 1 : we search the block where 15 bytes are the same and 
one is not (after decryption). Once we found it we search the position of this byte and than we make XOR
between it and the original byte in this block to find the position of the flipped bit. Once we have the 2
positions we know that we have to change the block ci in the ciphertext in the byte of the same position.
Than we change it and make a new decryption with the precedent function and return the real plaintext
"""


def cbc_flip_fix(k, n, cipher):
    #decryt cipher
    my_flipped_plaintext = cbc_custom_decrypt(k, n, cipher)
    my_blocks = []
    flag = 0
    byte_index = 0
    #separate each block
    for i in range(0, n):
        index = 16 * i
        my_blocks.append(my_flipped_plaintext[index: index + 16])
    #call function findFlippedBlock to check in which block was the flip
    flippedBlockNum = findFlippedBlock(my_blocks, n)
    #call function commonByte to find which is the byte that appear the most this will be the good byte
    common = commonByte(my_blocks[flippedBlockNum])
    #loop to find whi is the byte that was flipped
    for j in range(1, 16):
        if my_blocks[flippedBlockNum][0] == common:
            if my_blocks[flippedBlockNum][0] != my_blocks[flippedBlockNum][j]:
                byte_index = j
        else:
            byte_index = 0
    err = my_blocks[flippedBlockNum][byte_index]     #take the wrong byte
    err = "{:08b}".format(err) #convert him to binary
    common = "{:08b}".format(common) #convert the right byte to binary
    test_xor = bytesXOR(common, err) #check which bit was flipped with xor function
    cipher_index = 16 * (flippedBlockNum-1) + 16
    flippedCipherBlock = cipher[cipher_index:cipher_index+17] #recover the block that was wrong in the cipher
    flippedCipherByte = "{:08b}".format(flippedCipherBlock[byte_index]) #recover the byte that was wrong in the cipher and convert to binary
    newCipherByte = bytes([int(bytesXOR(test_xor, flippedCipherByte), 2)]) #reverse the wrong bit to the good and recover the new byte
    newCipher = cipher[:cipher_index + byte_index] + newCipherByte + cipher[cipher_index + byte_index + 1:] #create the new cipher with the modified bit
    block_plain_index = 16 * (flippedBlockNum - 1)
    my_temp = cbc_custom_decrypt(k, n, newCipher) #decrypt the new cipher
    my_decryption = my_temp[block_plain_index : block_plain_index + 16]
    return my_decryption #return the decrypt block that was wrong


# Function that return the byte that appears the most in a block
def commonByte(block):
    for i in range(0, 16):
        if block[i] == block[i+1]:
            return block[i]
        else:
            if block[i] == block[i+2]:
                return block[i]
            else:
                return block[i+1]


#Function to find the flipped block by compare all the bytes and return the index of the different byte
def findFlippedBlock(my_blocks, n):
    for i in range(1, n+1):
        for j in range(1, 16):
            right = my_blocks[n-i][0]
            left = my_blocks[n-i][j]
            test = right ^ left
            if test != 0:
                return n-i


# XOR for function 1
def XOR(a, b):
    my_result = bytearray()
    for a, b in zip(a, b):
        xor = a ^ b
        my_result.append(xor)
    return my_result


# XOR for function 2
def bytesXOR(a, b):
    xor = ""
    for x,y in zip(a,b):
        xor += str(int(x) ^ int(y))
    return xor

