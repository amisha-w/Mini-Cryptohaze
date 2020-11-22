import re 
import os
import requests
import argparse
from flask import Response
import concurrent.futures
import multiprocessing
import hashlib, random 


parser = argparse.ArgumentParser()
parser.add_argument('-s', help='hash', dest='hash')
parser.add_argument('-f', help='file containing hashes', dest='file')
parser.add_argument('-d', help='directory containing hashes', dest='dir')
parser.add_argument('-t', help='number of threads', dest='threads', type=int)
args = parser.parse_args()

#Colors
end = '\033[0m'
red = '\033[91m'
green = '\033[92m'
white = '\033[97m'
dgreen = '\033[32m'
yellow = '\033[93m'
back = '\033[7;91m'
run = '\033[97m[~]\033[0m'
que = '\033[94m[?]\033[0m'
bad = '\033[91m[-]\033[0m'
info = '\033[93m[!]\033[0m'
good = '\033[92m[+]\033[0m'

cwd = os.getcwd()
directory = args.dir
file = args.file
thread_count = args.threads or 4

cache_dict = {}
towrite = ""

with open("cachelist.txt", "r") as cachefile:
    for line in cachefile:
        if(line.find(":")!=-1):
            key,value = line.split(":")
            cache_dict[key] = value

if directory:
    if directory[-1] == '/':
        directory = directory[:-1]



def findReverseHash(hashvalue, hashtype):
    response = requests.get('https://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=deanna_abshire@proxymail.eu&code=1152464b80a61728' % (hashvalue, hashtype)).text
    if len(response) != 0:
        return response.strip("\n")
    else:
        return "Unable to crack."

def crackfile(file, word_dict=None, threads = 4):
    ans = []
    result.clear()
    try:
        miner(file, threads, word_dict)
    except KeyboardInterrupt:
        pass
    for hashvalue, cracked in result.items():
            ans.append([hashvalue,cracked.strip("\n")])
    return ans


def cracksingle(hashvalue, word_dict=None):
    if word_dict!=None and hashvalue in word_dict:
        return word_dict[hashvalue]
    if hashvalue in cache_dict:
        return cache_dict[hashvalue]
    else:
        resp = crack(hashvalue)
        if resp != None:
            with open("cachelist.txt","a") as f:
                if resp.strip("\n")!="Unable to crack.":
                    f.write("\n"+hashvalue+":"+resp.strip("\n"))
            cache_dict[hashvalue] = resp.strip("\n")
            return resp.strip("\n")
        return "Unable to crack."

def crack(hashvalue):
    if len(hashvalue) == 32:
        r = findReverseHash(hashvalue, 'md5')
        if r:
            return r
    elif len(hashvalue) == 40:
        r = findReverseHash(hashvalue, 'sha1')
        if r:
            return r
    elif len(hashvalue) == 64:
        r = findReverseHash(hashvalue, 'sha256')
        if r:
            return r
    elif len(hashvalue) == 96:
        r = findReverseHash(hashvalue, 'sha384')
        if r:
            return r
    elif len(hashvalue) == 128:
        r = findReverseHash(hashvalue, 'sha512')
        if r:
            return r
    else:
        return False

result = {}

def threaded(hashvalue, lock, word_dict):
    with lock:
        #check server cache & wordlist
        if word_dict!=None and hashvalue in word_dict:
            result[hashvalue] = word_dict[hashvalue]
        elif hashvalue in cache_dict:
            result[hashvalue] = cache_dict[hashvalue]
        else:
            #not found in cache
            resp = crack(hashvalue)
            if resp:
                result[hashvalue] = resp.strip("\n")
                with open("cachelist.txt","a") as f:
                    if resp.strip("\n")!="Unable to crack.":
                        f.write("\n"+hashvalue+":"+resp.strip("\n"))
                cache_dict[hashvalue] = resp.strip("\n")
            
def hash_type(hashvalue):
        if len(hashvalue) == 32:
                return "MD5"        
        elif len(hashvalue) == 40:
                return "SHA1"        
        elif len(hashvalue) == 64:
                return "SHA-256"
        elif len(hashvalue) == 96:
                return "SHA-384"           
        elif len(hashvalue) == 128:
                return "SHA-512"        
        return "This hash type is not supported." 

algo_dict = {"MD5":1,"SHA1":2, "SHA-256":3,"SHA-384":4,"SHA-512":5}

def encrypt(string,get_type=False):
    hashes = None
    if get_type:
        hashes = {}
        hashes[hashlib.md5(string.encode()).hexdigest()]="MD5"
        hashes[hashlib.sha256(string.encode()).hexdigest()]="SHA-256"
        hashes[hashlib.sha384(string.encode()).hexdigest()]="SHA-384"
        hashes[hashlib.sha512(string.encode()).hexdigest()]="SHA-512"  
        hashes[hashlib.sha1(string.encode()).hexdigest()]="SHA1"
        for i in hashes:
            with open("cachelist.txt","a") as f:
                f.write("\n"+i[0]+":"+string)
    else:
        hashes = []
        hashes.append(hashlib.md5(string.encode()).hexdigest()) 
        hashes.append(hashlib.sha256(string.encode()).hexdigest()) 
        hashes.append(hashlib.sha384(string.encode()).hexdigest())
        hashes.append(hashlib.sha512(string.encode()).hexdigest())  
        hashes.append(hashlib.sha1(string.encode()).hexdigest()) 
        for i in hashes:
            with open("cachelist.txt","a") as f:
                f.write("\n"+i+":"+string)
    return hashes

def encrypt_all(wordpath, get_type=False):
    if not get_type:
        word_dict = {}
        with open(wordpath,"r") as f:
            for line in f:
                word = line.strip("\n")
                for hash in encrypt(word):
                    word_dict[hash] = word
        return word_dict
    #hash with type
    encrypt_dict = {}
    with open(wordpath,"r") as f:
        for line in f:
            word = line.strip("\n")
            encrypt_dict[word] = encrypt(word,True)
    return encrypt_dict

def grepper(directory):    
    for file in os.listdir(directory):
        if file.endswith(".txt"):            
            try:
                miner(os.path.join(directory, file),threads=4)
            except KeyboardInterrupt:
                pass
            #Saves in Outer Dir. Try to save in specified Dir
            with open('cracked-%s' % file.split('\\')[-1], 'w+') as f:
                for hashvalue, cracked in result.items():
                    f.write(hashvalue + ':' + cracked + '\n')
            print ('%s Results saved in cracked-%s' % (info, os.path.join(directory, file).split('/')[-1]))

def returnResult():
    return result

def clearResult():
    result.clear()
    
def miner(file, threads, word_dict=None):
    lines = []
    found = set()
    with open(file, 'r') as f:
        for line in f:
            y = line.strip('\n')
            x = y.split('\t')
            for i in x:             
                lines.append(i)
    for line in lines:
        matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
        if matches:
            for match in matches:
                found.add(match)
    # print ('%s Hashes found: %i' % (info, len(found)))
    m = multiprocessing.Manager()
    lock = m.Lock()
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=int(threads))
    futures = (threadpool.submit(threaded, hashvalue, lock, word_dict) for hashvalue in found)
    for i, _ in enumerate(concurrent.futures.as_completed(futures)):
        # a = 1
        if i + 1 == len(found) or (i + 1) % 100 == 0: 
            # time elapsed ==1s or 0.5s
            print('%s Progress: %i/%i' % (info, i + 1, len(found)), end='\r')