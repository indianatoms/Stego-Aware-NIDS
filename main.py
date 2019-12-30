
import random

key = "superkey"


def changeToBinary(x):
    keybin = ""
    if len(x) < 8 :
        print("Choose another Key")
        return 0
    if len(x) > 8:
        x = x[0:7]
        print("You Key has been cut to eight characters: "+ x)
    for char in x:
    #       print(char)
    #ord prints the ascii value
    #        print(ord(char))
    #        print(bin(ord(char)))
            x = bin(ord(char))
            keybin = keybin + x
    #print(keybin.replace('b',''))
    return keybin.replace('b','')



def permutation64to56(key64) :
    key56 = ""
    my_list = list(range(0, len(key64))) # list of integers from 1 to 99
    # adjust this boundaries to fit your needs
    random.shuffle(my_list)
    print (my_list)
    for i in range(0,56) :
        key56 = key56 + key64[my_list[i]]
    print(key56)
    
#print(changeToBinary(key))
key64 = changeToBinary(key)
permutation64to56(key64)

