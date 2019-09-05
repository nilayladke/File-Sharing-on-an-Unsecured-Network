'''
File Sharing on Unsecured Network With AES Encryption
'''

import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import Crypto.Cipher.AES as AES
from os import urandom
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import dropbox
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode
from array import *

global cr_key
global cr_private_key         #   we are declaring keys globally here 
global file_name
global local_path           #   local path of the file 
global pckdic               #   package dictionary 
global filename_array


global nonce
nonce = get_random_bytes(8)       # nonce is dclared golbally too which will be a random number of 8 bytes   


local_path = "/C:/User/LENOVO/Anaconda3/lib/Folder/user_data/"
file_name = "test.txt"
pckdic = file_name.split(".")

global key_file                       # store enc key 
key_file = "/encKey" + file_name

def createDir(path):        # create dir 
    if not os.path.exists(path):
        os.makedirs(path)

global get_filepath        # For file path
get_filepath = "/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/downloads/" + \
                     pckdic[0]
createDir(get_filepath)


def pad(user_data):                # converts data into hexacimal form 
    return user_data + b"\0" * (AES.block_size - len(user_data) % AES.block_size)


def unpad(user_data):              # getting back the original data
    return user_data.rstrip(b'\0')


def readFile():
    # fileName = "working-draft.txt
    with open(local_filePath + file_name) as in_file:           
        user_data = in_file.readlines()                      # Reads user file

    stringuser_data = ''.join(user_data)
  
    private_key = SHA256.new(stringuser_data).digest()       # generate hash key
    return stringuser_data, private_key                      # function readFiles returns user data & private hash key
	
def Create_keys(private_key):                                # creats public key and private key                   
    keys = RSA.generate(1024)                                 
    f = open('/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/keyManager/my_pvt_rsa_key.pem', 'w')
    f.write(keys.exportKey('PEM'))
    f.close()

    f = open('/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/keyManager/my_public_rsa_key.pem', 'r')
    public_key = RSA.importKey(f.read())

    f = open('/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/keyManager/my_public_rsa_key.pem', 'w')
    f.write(keys.public_key().exportKey('PEM'))
    f.close()
                                                             # function Create_keys returns public key
    return public_key                                        # which we will use to encrypt private key


def Encrypt_private_key(private_key):                        # takes private key as input 
    f = open('../keyManager/my_public_rsa_key.pem', 'r')
    public_key = RSA.importKey(f.read())
    encrypted_private_key = public_key.encrypt(pad(private_key), None)  # encrypts private key using public key
    return encrypted_private_key					                    # Returns encrypted_private_key


def encrypt():								                # Here we will create 512 byte ASE block 
    stringuser_data, private_key = readFile(); 				# Then put aes encrypted data of same block size into those blocks
    padded_user_data = pad(stringuser_data)   			    # [data block, 512 bytes]
    ctr = Counter.new(64, nonce)		 		            # pre-defined nonce = 8 bytes and counter = 64 bytes [8 * 64 = 512 bytes]			
    aes = AES.new(private_key, AES.MODE_CTR, counter=ctr)   # initial cipher 
    encrypted_data = aes.encrypt(padded_user_data)          # encrypted data before randomization
    init_vec = Random.new().read(AES.block_size);           # get the initialization vector of same block size
    return init_vec + encrypted_data, private_key           # Adds init_vec to encrypted data to increase randomness
	
def decrypt(encrypted_data, private_key):   				# Decrypts cipher data and private key             
	   encrypted_data = encrypted_data[AES.block_size:]		# Takes 512 bytes of cipher data received
       ctr = Counter.new(64, nonce)							# Get the counter value
        aes = AES.new(private_key, AES.MODE_CTR, counter=ctr)   # generates the intial cipher
        original_data = aes.decrypt(encrypted_data)             # Decrypts the data & gives the padded original data

        return unpad(original_data)								# Removes the padded data & returns original data
	
def authenticateApp():
    access_token =''
    dbx = dropbox.Dropbox(access_token)
    return access_token, dbx

    
    


def upload_File_And_Key_And_Get_Metadata(encrypted_data, encrypted_private_key, access_token, dbx):
    #try:
    # deduplication part => overwrite = True
    response = dbx.files_upload("/test/test.txt", encrypted_data)
    stringEncryptedKey = str(encrypted_private_key)
    #stringEncryptedKey = unicode(stringEncryptedKey , "utf-8")
    responseFromKey = dbx.files_upload("test/" + key_file_name, stringEncryptedKey)
    print "Alice, your encrypted file has been successfully uploaded !\n"
    '''except Exception as e:
        print "Alice - Error occured while uploading the file- "
        print e
        # print 'uploaded: ', response '''
    return access_token


def downloadFile(access_token):
    dbx = dropbox.Dropbox(access_token)
    # folder_metadata = client.metadata('/')
    # print 'metadata: ', folder_metadata
    metadata, f1 = dbx.files_download(packageDirectory[0] + "/" + key_file_name)

    f2 = open('/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/my_pvt_rsa_key.pem', 'r')
    pvtkey = RSA.importKey(f2.read())
    decrypted = pvtkey.decrypt(f1.read())

    metadata, f = dbx.files_download("/" + packageDirectory[0] + "/" + file_name)
    out = open(download_file_path + "/" + file_name, 'wb')
    out.write(decrypt(encrypted_data, private_key))
    out.close()


def bob_generate_Rsa_Key_Pair():
    keys = RSA.generate(1024)
    f = open('/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/bob/bob_pvt_rsa_key.pem', 'w')
    f.write(keys.exportKey('PEM'))
    f.close()

    f = open('/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/bob/bob_public_rsa_key.pem', 'w')
    f.write(keys.public_key().exportKey('PEM'))
    f.close()


def alice_shares_with_bob():
    '''
    Alice gets her own encrypted key from dropbox
    decrypts the key
    '''
    dbx = dropbox.Dropbox(access_token)
    metadata, f1 = dbx.files_download(packageDirectory[0] + "/" + key_file_name)
    f2 = open('/C:/User/LENOVO/Anaconda3/lib/Folder/keyManager/my_pvt_rsa_key.pem', 'r')
    pvtkey = RSA.importKey(f2.read())
    decryptedKey = pvtkey.decrypt(f1.read())

    '''
    Re-seal this decrypted key with bobs_public_key
    '''
    f = open('../keyManager/bob/bob_public_rsa_key.pem', 'r')
    public_key = RSA.importKey(f.read())
    encrypted_private_keyForBob = public_key.encrypt(pad(decryptedKey), None)
    return encrypted_private_keyForBob;


def printStatus(msg):
    print msg


print "* * * * * * * * * * * * * * * * * * * * * * * * * * * * \n"
print " Secure Cloud Storage\n\n"
printStatus(
    " Hi I am Alice, I have file : " + file_name + " to process")
print "* * * * * * * * * * * * * * * * * * * * * * * * * * * * \n"

printStatus("Encrypting ")
encrypted_data, private_key = encrypt()
printStatus(" Encryption Completed\n")

printStatus("Creating Alice's RSA Public Key\n")
rsa_public_key = generate_Rsa_Key_Pair(private_key);

printStatus("Your Encrypted key is ready\n")
encrypted_private_key = getencrypted_private_key(private_key);

printStatus("Alice, Can you please authenticate your app ? \n");
access_token, client = authenticateApp()
print "Authentication successful ! \n "

printStatus("Uploading alice's file ")
access_token = upload_File_And_Key_And_Get_Metadata(encrypted_data, encrypted_private_key, access_token, client)

while (1):
    print "\n What do you want to do next . . .\n 1. Download the file \n 2. Share the file with friend\n 3. Change file name \n 4. Exit\n"
    user_choice = int(input("Enter your choice here : "))
    if user_choice == 1:

        print "\n \n Initialize Downloading \n"
        download_file_path = "/C:/User/LENOVO/Anaconda3/lib/Folder/downloads/" + \
                             packageDirectory[0]
        createDirStructure(download_file_path)

        printStatus("Downloading the file - " + file_name + " \n Download location - " + download_file_path)
        downloadFile(access_token);
        printStatus("Download Completed !")

    elif user_choice == 2:
        print "\n \n SHARE FILE \n"

        print "Hello Alice!\n You can only share your key with BOB"
        friend_id = int(input("Enter the friend id here : "))

        if (friend_id == 1):
            bob_generate_Rsa_Key_Pair()
            printStatus("Hi, I am Alice!")
            printStatus("I am re-sealing this key with Bobs public key")

            encrypted_private_keyForBob = alice_shares_with_bob()

            printStatus("\n For the sake of the code , Lets assume that Bob gets the required data ! \n");

            download_file_path = "/C:/User/LENOVO/Anaconda3/lib/Folder/sharedFiles/downloads" + "/ForBob/" + \
                                 packageDirectory[0]
            createDirStructure(download_file_path)

            access_token = upload_File_And_Key_And_Get_Metadata(encrypted_data, encrypted_private_keyForBob, access_token,
                                                                client)

            printStatus("And Bob downloads file successfully decrypting it")

            printStatus(" Downloading the file - " + file_name + " \n Download location - " + download_file_path)
            downloadFile(access_token)
            printStatus("Check the downloaded file in the Folder ")
            # end of if freind Id == 1

    elif user_choice == 3:
        print "\n \n C H A N G E   F I L E N A M E \n"
        all_file_names_array = ["mrunal.txt", "sample.mp4", "favicon.ico", "sample.jpg", "sample.png",
                                "notfoundpage.html", "sample.html"]
        print "Files present in user_data folders: \n "
        for f in all_file_names_array:
            print f
        file_name = raw_input("Enter filename you want to use for this session : ")
        packageDirectory = file_name.split(".")
        # Store the encrypted key on dropbox with the following filename
        key_file_name = "/EncryptedKey" + file_name

        # Location of the file downloaded on local machine
        download_file_path = "/C:/User/LENOVO/Anaconda3/lib/Folder//downloads/" + \
                             packageDirectory[0]
        createDirStructure(download_file_path)

        printStatus("Data encryption in progress ")
        encrypted_data, private_key = encrypt()
        printStatus("Alice, your data is encrypted successfully!\n")

        printStatus("Creating new encrypted secret key\n")
        encrypted_private_key = getencrypted_private_key(private_key);

        printStatus("File upload in progress . . . ")
        access_token = upload_File_And_Key_And_Get_Metadata(encrypted_data, encrypted_private_key, access_token, client)


    elif user_choice == 4:
        print "Goodbye !"
 
    else:
        print "Incorrect entry ! :("
	
	
	
	
