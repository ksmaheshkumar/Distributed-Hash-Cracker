#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

# Distributed Hash Cracker.

# Coded by GWF (Guerrilla Warfare)
# https://twitter.com/GuerrillaWF

# Native imports.
import re
import os
import sys
import time
import json
import getopt
import socket
import string
import random
import sqlite3
import hashlib
import itertools
import threading
from core.libs import socks #Ripped lib.

# Dependency imports
import requests

class paint():

    # Console paint
    N = '\033[0m' #  (normal)
    W = '\033[1;37m' # white
    R = '\033[31m' # red
    G = '\033[32m' # green
    O = '\033[33m' # orange
    B = '\033[34m' # blue
    P = '\033[35m' # purple
    C = '\033[36m' # cyan
    T = '\033[93m' # tan
    Y = '\033[1;33m' # yellow
    GR = '\033[37m' # gray
    BR = '\033[2;33m' # brown

# TO DO:
# Maybe go out and get a new user-agent string
# Improve accuracy of session file check after password is found.
# Use regex to check each database file faster.

# Need to know information
MD5SIGN = paint.R+"[MD5]:"+paint.N
SHA1SIGN = paint.R+"[SHA1]:"+paint.N
SHA256SIGN = paint.R+"[SHA256]:"+paint.N
SHA384SIGN = paint.R+"[SHA384]:"+paint.N
SHA512SIGN = paint.R+"[SHA512]:"+paint.N
TYPE = paint.W+"[TYPE]:"+paint.N
INFO = paint.W+"[INFO]:"+paint.N
ERROR = paint.R+"[ERROR]:"+paint.N
QueryFailed = paint.R+"query failed!"+paint.N
QuerySuccess = paint.O+"Password found!"+paint.N
GLOBALUSERAGENT = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"}

# Brute force method in house dictionary
CHARS = string.letters + string.digits + string.punctuation

class UserInformation():
    """ User API credentials to acces json data inside home-brewed config file. """
    HTTP_PROXY = {} # Set the proxy yourself.
    SOCKS5_PROXY = [] # Set the proxy yourself.

    # When production code is published, change dict to an empty dict.
    HTTP_PROXY["http"] = ""
    #HTTP_PROXY["https"] = "" # Does not work at this time.
    SOCKS5_PROXY.append("127.0.0.1")
user = UserInformation()

class Utilities():

    def Acceleration(self, mtarget):
        """ Thread certain processes."""
        process = threading.Thread(target=mtarget)
        return process.start()

    # Get Socks 5 Requests | Will travel through here.
    def GetSOCKS5Request(self, url):
        """ Global get request w/browser UserAgent string."""
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, user.SOCKS5_PROXY[0], 9050) # TOR network socket
        socket.socket = socks.socksocket # use TOR
        GetRequestSession = requests.Session()
        response = GetRequestSession.get(url, headers=GLOBALUSERAGENT)
        return response # Just return the object, not the content.

    # Post Socks 5 Requests | Will travel through here.
    def PostSOCKS5Request(self, url, params):
        """ Global get request w/browser UserAgent string."""
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, user.SOCKS5_PROXY[0], 9050) # TOR network socket
        socket.socket = socks.socksocket # use TOR
        PostRequestSession = requests.Session()
        response = PostRequestSession.post(url, headers=GLOBALUSERAGENT, data=params)
        return response # Just return the object, not the content.

    # Get Requests HTTP style
    def GetHTTPRequest(self, url):
        GetRequestSession = requests.Session()
        GetRequestSession.proxies = user.HTTP_PROXY['http'] # Only accepts http at this time.
        response = GetRequestSession.get(url, headers=GLOBALUSERAGENT)
        return response # Just return the object, not the content.

    # Post Requests HTTP style
    def PostHTTPRequest(self, url, params):
        PostRequestSession = requests.Session()
        PostRequestSession.proxies = user.HTTP_PROXY['http']
        response = PostRequestSession.post(url, headers=GLOBALUSERAGENT, data=params)
        return response # Just return the object, not the content.
utilities = Utilities()

class FileOperations():

    def HashAWordList(self):

        """
        Turn ascii/plain-text/wordlists into hash:pass pairs.
        """

        try:

            with open(sys.argv[2], 'r') as wl:

                choice = raw_input("\nHash Type: ")
                fn5 = "newly_hashed_md5_wordlist.txt"
                fn1 = "newly_hashed_sha1_wordlist.txt"
                fn224 = "newly_hashed_sha224_wordlist.txt"
                fn256 = "newly_hashed_sha256_wordlist.txt"
                fn384 = "newly_hashed_sha384_wordlist.txt"
                fn512 = "newly_hashed_sha512_wordlist.txt"


                if choice == "md5":
                    time.sleep(2)
                    print INFO, "Turning your wordlist {} into ".format(paint.W+sys.argv[2]+paint.N)+paint.R+"[MD5] hash"+paint.N+":"+paint.B+"pass"+paint.N+" pairs ..."
                    with open(fn5, "w") as file:
                        for i in wl:
                            i = i.replace("\n",'')
                            md5 = hashlib.md5(i)
                            md5ers = md5.hexdigest() +":"+ i
                            file.write(md5ers + "\n")
                    time.sleep(2)
                    print INFO, "MD5 hash:pass pairs made."

                elif choice == "sha1":
                    with open(fn1, "w") as file:
                        for i in wl:
                            i = i.replace("\n", "")
                            sha1 = hashlib.sha1(i)
                            sha1ers = sha1.hexdigest() + ":" + i
                            file.write(sha1ers + "\n")
                            print "Wrote:", fn1

                elif choice == "sha224":
                    with open(fn224, "w") as file:
                        for i in wl:
                            i = i.replace("\n", "")
                            sha224 = hashlib.sha224(i)
                            sha224ers = sha224.hexdigest() + ":" + i
                            file.write(sha224ers + "\n")
                            print "Wrote:", fn224

                elif choice == "sha256":
                    with open(fn256, "w") as file:
                        for i in wl:
                            i = i.replace("\n", "")
                            sha256 = hashlib.sha256(i)
                            sha256ers = sha256.hexdigest() + ":" + i
                            file.write(sha256ers + "\n")
                            print "Wrote:",

                elif choice == "sha384":
                    with open(fn384, "w") as file:
                        for i in wl:
                            i = i.replace("\n", "")
                            sha384 = hashlib.sha384(i)
                            sha384ers = sha384.hexdigest() + ":" + i
                            file.write(sha384ers + "\n")

                elif choice == "sha512":
                    with open(fn512, "w") as file:
                        for i in wl:
                            i = i.replace("\n", "")
                            sha512 = hashlib.sha512(i)
                            sha512ers = sha512.hexdigest() + ":" + i
                            file.write(sha512ers + "\n")

                else:
                    usage()

        except Exception, e:
            print e
            print """
            Invalid wordlist."""
            usage()
            sys.exit(0)
fileoperations = FileOperations()

class DatabaseOperations():

    def QueryDatabaseForSingleHash(self, InputHash):

        """
        Ping/Query the database for a single given hash.
        """

        try:
            # MD5 Session file
            # re.findall(r"([a-fA-F\d]{32})", data)
            if len(InputHash) == 32:
                with open(os.path.dirname(__file__) + '/core/database/cracked_MD5_hashes.session', 'r') as md5_session_file:

                    #if len(InputHash) == 32: HTS = MD5SIGN

                    print "\n", INFO, "Checking your "+paint.Y+"MD5_session"+paint.N+" file for {} ...".format(paint.BR+InputHash+paint.N)

                    # The actual search
                    for x in md5_session_file:
                        x = x.replace("\n", "")

                        if len(InputHash) == 32: y = x[:32]
                        # y = x[:32] only look through md5 hashes

                        # Compare hashes to to hashes in session file.
                        if InputHash in y:
                            time.sleep(1)
                            print INFO, QuerySuccess
                            time.sleep(2)
                            print INFO, "Password is:", paint.C+x[33:]+paint.N + "\n"
                            time.sleep(2)
                            break

                    if InputHash not in y: # Some form of decision making.
                        time.sleep(2)
                        print INFO, paint.BR+InputHash+paint.N, "was not found in your "+paint.Y+"MD5_session"+paint.N+" file.\n"
                        time.sleep(1)
                        sys.exit(0)

            elif len(InputHash) == 40:
                # re.findall(r"([a-fA-F\d]{40})", data)
                with open(os.path.dirname(__file__) + '/core/database/cracked_SHA1_hashes.session', 'r') as sha1_session_file:
                    #if len(InputHash) == 40: HTS = SHA1SIGN

                    print "\n", INFO, "Checking your "+paint.Y+"SHA1_session"+paint.N+" file for {} ...".format(paint.BR+InputHash+paint.N)

                    for x in sha1_session_file:
                        x = x.replace("\n", "")

                        if len(InputHash) == 40: y = x[:40]
                        # y = x[:40] only look through sha1 hashes

                        if InputHash in y:
                            time.sleep(2)
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is:", paint.C+x[41:]+paint.N + "\n"
                            time.sleep(2)
                            break

                    if InputHash not in y: # Some form of decision making.
                        time.sleep(2)
                        print INFO, paint.BR+InputHash+paint.N, "was not found in your "+paint.Y+"SHA1_session"+paint.N+" file.\n"
                        time.sleep(1)
                        sys.exit(0)

                    #with open(os.path.dirname(__file__) + '/core/database/cracked_SHA224_hashes.session', 'r') as sha224_session_file:

            elif len(InputHash) == 64:
                # re.findall(r"([a-fA-F\d]{64})", data)
                with open(os.path.dirname(__file__) + '/core/database/cracked_SHA256_hashes.session', 'r') as sha256_session_file:

                    #if len(InputHash) == 64: HTS = SHA256SIGN

                    print "\n", INFO, "Checking your "+paint.Y+"SHA256_session"+paint.N+" file for {} ...".format(paint.BR+InputHash+paint.N)

                    for x in sha256_session_file:
                        x = x.replace("\n", "")

                        if len(InputHash) == 64: y = x[:64]
                        # y = x[:40] only look through sha256 hashes

                        if InputHash in y:
                            time.sleep(2)
                            print INFO, QuerySuccess
                            time.sleep(2)
                            print INFO, "Password is:", paint.C+x[65:]+paint.N + "\n"
                            time.sleep(2)
                            break

                    if InputHash not in y: # Some form of decision making.
                        time.sleep(2)
                        print INFO, paint.BR+InputHash+paint.N, "was not found in your "+paint.Y+"SHA256_session"+paint.N+" file.\n"
                        time.sleep(1)
                        sys.exit(0)


            elif len(InputHash) == 96:
                # re.findall(r"([a-fA-F\d]{96})", data)
                with open(os.path.dirname(__file__) + '/core/database/cracked_SHA384_hashes.session', 'r') as sha384_session_file:

                    #if len(InputHash) == 96: HTS = SHA384SIGN

                    print "\n", INFO, "Checking your "+paint.Y+"SHA384_session"+paint.N+" file for {} ...".format(paint.BR+InputHash+paint.N)

                    for x in sha384_session_file:
                        x = x.replace("\n", "")

                        # Compare hashes to to hashes in session file.
                        if InputHash in y:
                            #print x | for debugging output.

                            if len(InputHash) == 96: y = x[:96]
                            # y = x[:40] only look through sha2384 hashes

                            if InputHash in y:
                                time.sleep(2)
                                print INFO, QuerySuccess
                                time.sleep(2)
                                print INFO, "Password is:", paint.C+x[97:]+paint.N + "\n"
                                time.sleep(2)
                                break

                    if InputHash not in y: # Some form of decision making.
                        time.sleep(2)
                        print INFO, paint.BR+InputHash+paint.N, "was not found in your "+paint.Y+"SHA384_session"+paint.N+" file.\n"
                        time.sleep(1)
                        sys.exit(0)

            elif len(InputHash) == 128:
                # re.findall(r"([a-fA-F\d]{128})", data)
                with open(os.path.dirname(__file__) + '/core/database/cracked_SHA512_hashes.session', 'r') as sha512_session_file:

                    #if len(InputHash) == 128: HTS = SHA512SIGN

                    print "\n", INFO, "Checking your "+paint.Y+"SHA512_session"+paint.N+" file for {} ...".format(paint.BR+InputHash+paint.N)

                    # The actual search
                    for x in sha512_session_file:
                        x = x.replace("\n", "")

                        # Compare hashes to to hashes in session file.
                        if InputHash in y:
                            #print x | for debugging output.

                            if len(InputHash) == 128: y = x[:128]
                            # y = x[:40] only look through sha2384 hashes

                            if len(InputHash) == 128:
                                time.sleep(2)
                                print INFO, QuerySuccess
                                time.sleep(2)
                                print INFO, "Password is:", paint.C+x[129:]+paint.N + "\n"
                                time.sleep(2)
                                break

                    if InputHash not in x: # Some form of decision making.
                        time.sleep(2)
                        print INFO, paint.BR+InputHash+paint.N, "was not found in your "+paint.Y+"SHA512_session"+paint.N+" file.\n"
                        time.sleep(1)
                        sys.exit(0)

        except IOError as e:
            #print e
            print INFO, ""+paint.Y+"Session"+paint.N+" file(s) not found!\n"

    def QueryDatabaseWithFile(self):
        """ Query the session file with file of hashes and display results."""
        pass

    def LoadHashedWordlistIntoDatabse():
        """ Load a hashed wordlist into your session file. """
        # Detect the hash:pass format
        pass

    def WriteMD5PairToFile(self, InputHash, Password):
        print INFO, "checking the "+paint.Y+"MD5_session"+paint.N+" file for the above Hash/Password pair ..."
        # print INFO, "Writing hash/password pair to disk ..."
        with open(os.path.dirname(__file__) + '/core/database/cracked_MD5_hashes.session', 'a') as file:
            with open(os.path.dirname(__file__) + '/core/database/cracked_MD5_hashes.session', 'r') as f:
                for x in f:
                    if InputHash in x:
                        time.sleep(2)
                        print INFO, "Hash/Password pair already recorded.\n"
                        sys.exit(0)
                time.sleep(1)
                print INFO, "Hash/Password pair not found in the "+paint.Y+"MD5_session"+paint.N+" file ..."
                time.sleep(2)
                print INFO, "Writing hash/password pair to the "+paint.Y+"MD5_session"+paint.N+" file ...\n"
                file.write(InputHash + ":")
                file.write(Password + "\n")
                time.sleep(2)
                sys.exit(0)

    def WriteSHA1PairToFile(self, InputHash, Password):
        print INFO, "checking the "+paint.Y+"SHA1_session"+paint.N+" file for the above Hash/Password pair ..."
        # print INFO, "Writing hash/password pair to disk ..."
        with open(os.path.dirname(__file__) + '/core/database/cracked_SHA1_hashes.session', 'a') as file:
            with open(os.path.dirname(__file__) + '/core/database/cracked_SHA1_hashes.session', 'r') as f:
                for x in f:
                    if InputHash in x:
                        time.sleep(2)
                        print INFO, "Hash/Password pair already recorded.\n"
                        sys.exit(0)
                #print INFO, "Hash/Password pair not"
                time.sleep(2)
                print INFO, "Hash/Password pair not found in the "+paint.Y+"SHA1_session"+paint.N+" file."
                time.sleep(2)
                print INFO, "Writing hash/password pair to the "+paint.Y+"SHA1_session"+paint.N+" file ...\n"
                file.write(InputHash + ":")
                file.write(Password + "\n")
                time.sleep(2)
                sys.exit(0)

    def WriteSHA224PairToFile(self, InputHash, Password):
        print INFO, "checking the "+paint.Y+"SHA224_session"+paint.N+" file for the above Hash/Password pair ..."
        # print INFO, "Writing hash/password pair to disk ..."
        with open(os.path.dirname(__file__) + '/core/database/cracked_SHA224_hashes.session', 'a') as file:
            with open(os.path.dirname(__file__) + '/core/database/cracked_SHA224_hashes.session', 'r') as f:
                for x in f:
                    if InputHash in x:
                        time.sleep(2)
                        print INFO, "Hash/Password pair already recorded.\n"
                        sys.exit(0)
                #print INFO, "Hash/Password pair not"
                time.sleep(2)
                print INFO, "Hash/Password pair not found in the "+paint.Y+"SHA224_session"+paint.N+" file."
                time.sleep(2)
                print INFO, "Writing hash/password pair to the"+paint.Y+"SHA224_session"+paint.N+" file ...\n"
                file.write(InputHash + ":")
                file.write(Password + "\n")
                time.sleep(2)
                sys.exit(0)

    def WriteSHA256PairToFile(self, InputHash, Password):
        print INFO, "checking the SHA256 "+paint.Y+"session"+paint.N+" file for the above Hash/Password pair ..."
        # print INFO, "Writing hash/password pair to disk ..."
        with open(os.path.dirname(__file__) + '/core/database/cracked_SHA256_hashes.session', 'a') as file:
            with open(os.path.dirname(__file__) + '/core/database/cracked_SHA256_hashes.session', 'r') as f:
                for x in f:
                    if InputHash in x:
                        time.sleep(2)
                        print INFO, "Hash/Password pair already recorded.\n"
                        sys.exit(0)
                #print INFO, "Hash/Password pair not"
                print INFO, "Hash/Password pair not found in "+paint.Y+"session"+paint.N+" file."
                time.sleep(2)
                print INFO, "Writing hash/password pair to "+paint.Y+"session"+paint.N+" file ...\n"
                file.write(InputHash + ":")
                file.write(Password + "\n")
                time.sleep(2)
                sys.exit(0)

    def WriteSHA384PairToFile(self, InputHash, Password):
        print INFO, "checking the SHA384 "+paint.Y+"session"+paint.N+" file for the above Hash/Password pair ..."
        # print INFO, "Writing hash/password pair to disk ..."
        with open(os.path.dirname(__file__) + '/core/database/cracked_SHA384_hashes.session', 'a') as file:
            with open(os.path.dirname(__file__) + '/core/database/cracked_SHA384_hashes.session', 'r') as f:
                for x in f:
                    if InputHash in x:
                        time.sleep(2)
                        print INFO, "Hash/Password pair already recorded.\n"
                        sys.exit(0)
                #print INFO, "Hash/Password pair not"
                print INFO, "Hash/Password pair not found in "+paint.Y+"session"+paint.N+" file."
                time.sleep(2)
                print INFO, "Writing hash/password pair to "+paint.Y+"session"+paint.N+" file ...\n"
                file.write(InputHash + ":")
                file.write(Password + "\n")
                time.sleep(2)
                sys.exit(0)

    def WriteSHA512PairToFile(self, InputHash, Password):
        print INFO, "checking the SHA512 "+paint.Y+"session"+paint.N+" file for the above Hash/Password pair ..."
        # print INFO, "Writing hash/password pair to disk ..."
        with open(os.path.dirname(__file__) + '/core/database/cracked_SHA512_hashes.session', 'a') as file:
            with open(os.path.dirname(__file__) + '/core/database/cracked_SHA512_hashes.session', 'r') as f:
                for x in f:
                    if InputHash in x:
                        time.sleep(2)
                        print INFO, "Hash/Password pair already recorded.\n"
                        sys.exit(0)
                #print INFO, "Hash/Password pair not"
                print INFO, "Hash/Password pair not found in "+paint.Y+"session"+paint.N+" file."
                time.sleep(2)
                print INFO, "Writing hash/password pair to "+paint.Y+"session"+paint.N+" file ...\n"
                file.write(InputHash + ":")
                file.write(Password + "\n")
                time.sleep(2)
                sys.exit(0)
databaseoperations = DatabaseOperations()

class HashCracking():
# Hash Brute Forcing ----------------------------------------------------------------
    def BruteForceByWordList(self, InputHash):

        wordlist = sys.argv[4]

        with open(wordlist, 'r') as f:
            print "\n", INFO,"Loaded words from {}".format(wordlist)
            for line in f:
                #print TYPE, MD5SIGN, paint.B+InputHash+paint.N
                if len(InputHash) == 32:
                    #time.sleep(1)
                    hash = hashlib.md5()
                    hash.update(line[:-1])
                    if InputHash in hash.hexdigest():
                        time.sleep(1)
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is:", paint.C+line+paint.N
                        time.sleep(2)
                        WriteMD5PairToFile(InputHash, line)

            if hash.hexdigest() not in InputHash:
                time.sleep(1)
                print INFO, "Your wordlist "+paint.R+"failed"+paint.N+", try another wordlist.\n"
                time.sleep(1)
                sys.exit(0)

    """
                elif len(InputHash) == 40:
                    time.sleep(1)
                    print TYPE, SHA1SIGN, paint.B+InputHash+paint.N
                    for word in words:
                        hash = hashlib.sha1(word[:-1])
                        if hash.hexdigest() in InputHash:
                            time.sleep(1)
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is:", paint.C+word.replace("\n", "")+paint.N
                            time.sleep(2)
                            WriteMD5PairToFile(InputHash, word)

                    if hash.hexdigest() not in InputHash.lower():
                        time.sleep(1)
                        print INFO, "Your wordlist "+paint.R+"failed"+paint.N+" try another wordlist."
                        time.sleep(1)
                        sys.exit(0)


                elif len(InputHash) == 64:
                    time.sleep(1)
                    print TYPE, SHA256SIGN, paint.B+InputHash+paint.N
                    for word in words:
                        hash = hashlib.sha256(word[:-1])
                        if hash.hexdigest()in InputHash:
                            time.sleep(1)
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is:", paint.C+word.replace("\n", "")+paint.N
                            time.sleep(2)
                            WriteMD5PairToFile(InputHash, word)

                    if hash.hexdigest() not in InputHash:
                        time.sleep(1)
                        print INFO, "Your wordlist "+paint.R+"failed"+paint.N+" try another wordlist."
                        time.sleep(1)
                        sys.exit(0)

                elif len(InputHash) == 96:
                    time.sleep(1)
                    print TYPE, SHA384SIGN, paint.B+InputHash+paint.N
                    for word in words:
                        hash = hashlib.sha384(word[:-1])
                        if hash.hexdigest()in InputHash:
                            time.sleep(1)
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is:", paint.C+word.replace("\n", "")+paint.N
                            time.sleep(2)
                            WriteMD5PairToFile(InputHash, word)

                    if hash.hexdigest() not in InputHash:
                        time.sleep(1)
                        print INFO, "Your wordlist "+paint.R+"failed"+paint.N+" try another wordlist."
                        time.sleep(1)
                        sys.exit(0)

                else:
                    print "\n   ", ERROR, "Hash value length not supported!"
                    usage()
    """
    """
        elif len(algo) == 128:
        	for word in words:
        		hash = hashlib.sha512(word[:-1])
        		value = hash.hexdigest()
        		if pw == value:
                    print INFO, QuerySuccess
                    time.sleep(1)
                    print INFO, "Password is:", word ,"\n"
                    time.sleep(1)
                    with open('cracked_hash_passwords.txt', 'a') as file:
                        file.write("\nCracked [MD5] Hashes:\n")
                        file.write(pw + ":")
                        file.write(word + "\n")
                        """

    def BruteForceByAlgorithm(self, InputHash):
        start_time = time.time()
        if len(InputHash) == 32:
            for length in range(0,20):
                for entry in itertools.product(CHARS ,repeat = length):
                    password = ''.join(entry)
                    m = hashlib.md5()
                    m.update(password)
                    if m.hexdigest() == InputHash.lower():
                        stop_time = time.time()
                        print INFO, QuerySuccess
                        time.sleep(0)
                        time.sleep(2)
                        print INFO, "Password is:", paint.C+password+paint.N
                        print INFO, "cracked in", int(float(stop_time - start_time)),"seconds."
                        databaseoperations.WriteMD5PairToFile(InputHash, password)
                        sys.exit(0)
                time.sleep(2)
                print INFO, "Trying "+paint.W+"{0}".format(len(password) + 1)+paint.N+" character passwords against "+paint.C+"{0}".format(InputHash)+paint.N+" "

        elif len(InputHash) == 40:
            for length in range(0,20):
                for entry in itertools.product(CHARS ,repeat = length):
                    password = ''.join(entry)
                    m = hashlib.sha1()
                    m.update(password)
                    if m.hexdigest() == InputHash.lower():
                        time.sleep(2)
                        print INFO, QuerySuccess
                        time.sleep(2)
                        print INFO, "Password is:", paint.C+password+paint.N
                        print INFO, "cracked in", int(float(stop_time - start_time)),"seconds."
                        databaseoperations.WriteSHA1PairToFile(InputHash, password)
                        sys.exit(0)
                time.sleep(2)
                print INFO, "Trying "+paint.W+"{0}".format(len(password) + 1)+paint.N+" character passwords against "+paint.C+"{0}".format(InputHash)+paint.N+" "

        elif len(InputHash) == 64:
            for length in range(0,20):
                for entry in itertools.product(CHARS ,repeat = length):
                    password = ''.join(entry)
                    m = hashlib.sha256()
                    m.update(password)
                    if m.hexdigest() == InputHash.lower():
                        time.sleep(2)
                        print INFO, QuerySuccess
                        time.sleep(2)
                        print INFO, "Password is:", paint.C+password+paint.N
                        print INFO, "cracked in", int(float(stop_time - start_time)),"seconds."
                        databaseoperations.WriteSHA256PairToFile(InputHash, password)
                        sys.exit(0)
                time.sleep(2)
                print INFO, "Trying "+paint.W+"{0}".format(len(password) + 1)+paint.N+" character passwords against "+paint.C+"{0}".format(InputHash)+paint.N+" "

        elif len(InputHash) == 96:
            for length in range(0,20):
                for entry in itertools.product(CHARS ,repeat = length):
                    password = ''.join(entry)
                    m = hashlib.sha384()
                    m.update(password)
                    if m.hexdigest() == InputHash:
                        time.sleep(2)
                        print INFO, QuerySuccess
                        time.sleep(2)
                        print INFO, "Password is:", paint.C+password+paint.N
                        print INFO, "cracked in", int(float(stop_time - start_time)),"seconds."
                        databaseoperations.WriteSHA384PairToFile(InputHash, password)
                        sys.exit(0)
                time.sleep(2)
                print INFO, "Trying "+paint.W+"{0}".format(len(password) + 1)+paint.N+" character passwords against "+paint.C+"{0}".format(InputHash)+paint.N+" "

        elif len(InputHash) == 128:
            for length in range(0,20):
                for entry in itertools.product(CHARS ,repeat = length):
                    password = ''.join(entry)
                    m = hashlib.sha512()
                    m.update(password)
                    if m.hexdigest() == InputHash:
                        time.sleep(2)
                        print INFO, QuerySuccess
                        time.sleep(2)
                        print INFO, "Password is:", paint.C+password+paint.N
                        print INFO, "cracked in", int(float(stop_time - start_time)),"seconds."
                        databaseoperations.WriteSHA512PairToFile(InputHash, password)
                        sys.exit(0)
                time.sleep(2)
                print INFO, "Trying "+paint.W+"{0}".format(len(password) + 1)+paint.N+" character passwords against "+paint.C+"{0}".format(InputHash)+paint.N+" "

        else:
            usage()

    def BruteForceByCrossHashReferencingHash(self, HashFile, WordlistFile):
        # Read the hash file entered
        # Read the wordlist file entered

        # compare newly hashed words to already each line in hash file

            wordlist = sys.argv[3]
            hashlist = sys.argv[4]

            try:
                wordlistfile = open(wordlist, "r")
            except IOError:
                print INFO, ERROR,"Check your wordlist path\n"
                sys.exit(1)

            try:
                hashlistfile = open(hashlist, "r")
            except IOError:
                print INFO, ERROR,"Check your wordlist path\n"
                sys.exit(1)

            if len(InputHash) == 32:
                print "\n", INFO,"Loaded {} words from {}".format(len(words) ,wordlist)
                time.sleep(1)
                print TYPE, MD5SIGN, paint.B+InputHash+paint.N
                for word in words:
                    hash = hashlib.md5()
                    hash.update(word[:-1])
                    if HashFile in hash.hexdigest():
                        time.sleep(1)
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is:", paint.C+word.replace("\n", "")+paint.N
                        time.sleep(2)
                        databseoperations.WriteMD5PairToFile(HashFile, word)
hashcracking = HashCracking()

class WatchList():

    def MonitorTwitterHashStream(self):
        pass

    def MonitorDumpMonitor(self):
        # https://twitter.com/hashtag/infoleak?f=realtime&src=hash
        pass

    def MonitorPastebinDorks(self):
        pass

    def MonitorPastie(self):
        pass

    def MonitorLeakedIn(self):
        # open each link
        # examine each <pre>32hex:pass</pre>
        # pull each hash
        pass

    def MonitorPasteBinArchive(self):
        time_between = 7       #Seconds between iterations (not including time used to fetch pages - setting below 5s may cause a pastebin IP block, too high may miss pastes)
        error_on_cl_args = "Please provide a single regex search via the command line"   #Error to display if improper command line arguments are provided

        # Check for command line argument (a single regex)
        if len(sys.argv) != 1:
            search_term = sys.argv[1]
        else:
            print error_on_cl_args
            exit()

        iterater = 1

        while(1):
            counter = 0

            print "Scanning pastebin - iteration " + str(iterater) + "..."

            #Open the recently posted pastes page
            try:
                html = utilities.GetSOCKS5Request("http://pastebin.com/archive")
                html_lines = html.split('\n')
                for line in html_lines:
                    if counter < 10:
                        if re.search(r'<td><img src=\"/i/t.gif\"  class=\"i_p0\" alt=\"\" border=\"0\" /><a href=\"/[0-9a-zA-Z]{8}">.*</a></td>', line):
                            link_id = line[72:80]
                            #print link_id

                            #Begin loading of raw paste text
                            url_2 = utilities.GetSOCKS5Request("http://pastebin.com/raw.php?i=" + link_id)
                            raw_text = url_2.read()
                            url_2.close()

                            #if search_term in raw_text:
                            if re.search(r''+search_term, raw_text):
                                print "FOUND " + search_term + " in http://pastebin.com/raw.php?i=" + link_id

                            counter += 1
            except(IOError):
                print "Network error - are you connected?"
            except:
                print "Fatal error! Exiting."
                exit()
            iterater += 1
            time.sleep(time_between)

class HashFindings():
    # Hash finding/Methods -----------------------------------------------------------------------------------

    def FindSHA1onStringFunction(self, sha1erhash):

        ReturnedParams = {"string":"{}".format(sha1erhash), "submit":"Decrypt"}
        PostResponse = utilities.PostSOCKS5Request("http://www.stringfunction.com/sha1-decrypter.html", ReturnedParams).text
        PasswordData = PostResponse.split()
        for line in PasswordData:
            line = line.strip()
            if 'name="result">' in line:
                line = line.replace('name="result">', "").replace("</textarea>", "") # Get the actual password
                return line

    def FindMD5onStringFunction(self, md5erhash):

        ReturnedParams = {"string":"{}".format(md5erhash), "submit":"Decrypt"}
        PostResponse = utilities.PostSOCKS5Request("http://www.stringfunction.com/md5-decrypter.html", ReturnedParams).text
        PasswordData = PostResponse.split()
        for line in PasswordData:
            line = line.strip()
            if 'name="result">' in line:
                line = line.replace('name="result">', "").replace("</textarea>", "") # Get the actual password
                return line

    def FindHashOnHashesDotORG(self, HashReq):
        APIres = utilities.GetSOCKS5Request("https://hashes.org/api.php?do=check&hash1={0}&format=json".format(HashReq)).text
        return APIres.replace("'", '"')

    def FindMD5HashOnMD5Cracker(self, md5hash):
        MD5C_response = utilities.GetSOCKS5Request("http://md5cracker.org/api/api.cracker.php?r=8255&database=md5cracker.org&hash={}".format(md5hash)).text
        return json.loads(MD5C_response)

    def FindMd5oninsomnia247(self, MD5hash):

        if len(MD5hash) <= 31:
            print INFO, paint.R+"Not an md5 hash!"+paint.N
            usage()
            sys.exit(0)

        elif len(MD5hash) == 32:
            #print "\n" + INFO, "querying "+paint.C+"insomnia247"+paint.N+" ..."
            MD5Request = utilities.GetSOCKS5Request("https://www.insomnia247.nl/hash_api.php?type=md5&hash={0}".format(MD5hash)).text
            return MD5Request

    def FindSHA1insomnia247(self, SHA1hash):

        if len(SHA1hash) <= 39:
            print INFO, paint.R+"Not a sha1 hash!"+paint.N
            usage()
            sys.exit(0)

        elif len(SHA1hash) == 40:
            #print "\n" + INFO, "Querying "+paint.C+"insomnia247"+paint.N+" ..."
            SHA1Request = utilities.GetSOCKS5Request("https://www.insomnia247.nl/hash_api.php?type=sha1&hash={0}".format(SHA1hash)).text
            return SHA1Request

    # Search through Google | with different cases.
    def FindHashUsingGoogle(self, Hash):
        # Modified algorithm; to work for the users specific possible hash types.
        HashRequest = utilities.GetHTTPRequest("https://www.google.com/search?q={}".format(Hash)).content
        wordlist = HashRequest.split()

        # MD5
        if len(Hash) == 32:
            for word in wordlist:
                word = word.strip()
                #TO DO: check which algorithm is used, and use the correct one
                #for now it is md5
                m = hashlib.md5()
                m.update(word)
                if m.hexdigest() == Hash:
                    return bytes.decode(word)

        # Sha1
        elif len(Hash) == 40:

            for word in wordlist:
                word = word.strip()
                #TO DO: check which algorithm is used, and use the correct one
                #for now it is md5
                m = hashlib.sha1()
                m.update(word)
                if m.hexdigest() == Hash:
                    return bytes.decode(word)

        # Sha256
        elif len(Hash) == 64:

            for word in wordlist:
                word = word.strip()
                #TO DO: check which algorithm is used, and use the correct one
                #for now it is md5
                m = hashlib.sha256()
                m.update(word)
                if m.hexdigest() == Hash:
                    return bytes.decode(word)

        # Sha224
        elif len(Hash) == 56:

            for word in wordlist:
                word = word.strip()
                #TO DO: check which algorithm is used, and use the correct one
                #for now it is md5
                m = hashlib.sha224()
                m.update(word)
                if m.hexdigest() == Hash:
                    return bytes.decode(word)

        # Sha384
        elif len(Hash) == 96:

            for word in wordlist:
                word = word.strip()
                #TO DO: check which algorithm is used, and use the correct one
                #for now it is md5
                m = hashlib.sha384()
                m.update(word)
                if m.hexdigest() == Hash:
                    return bytes.decode(word)

        # Sha512
        elif len(Hash) == 128:

            for word in wordlist:
                word = word.strip()
                #TO DO: check which algorithm is used, and use the correct one
                #for now it is md5
                m = hashlib.sha512()
                m.update(word)
                if m.hexdigest() == Hash:
                    return bytes.decode(word)

    # Leak Database json-api | includes rate limiting.
    def FindHashLeakDB(self, HASH):
        HashRequest = utilities.GetSOCKS5Request("https://api.leakdb.net/?j={0}".format(HASH)).text
        return json.loads(HashRequest)

    # MD5DB | Random website with free json-api
    def FindMD5onMD5DB(self, MD5Hash):

        if len(MD5Hash) <= 31:
            print INFO, paint.R+"Not an md5 hash!"+paint.N
            usage()
            sys.exit(0)

        if len(MD5Hash) == 32:
            MD5Request = utilities.GetSOCKS5Request("http://md5db.net/api/{0}".format(MD5Hash)).text
            return MD5Request

    # MD5DECODE | Random website with free api
    def FindMD5onMD5DECODE(self, MD5):
        # This method will always retur na NoneType response when pushing TOR traffic.
        if len(MD5) <= 31:
            print INFO, paint.R+"Not an md5 hash!"+paint.N
            usage()
            sys.exit(0)

        if len(MD5) == 32:
            try:
                md5request = utilities.GetSOCKS5request("http://www.md5decode.com/decrypt/{}".format(MD5)).content
                return md5request
            except:
                #print INFO, QueryFailed
                pass

    def FindMD5onHashToolkit(self, MD5hash):
        HTKR = utilities.GetSOCKS5Request("http://hashtoolkit.com/reverse-hash?hash={}".format(MD5hash)).text
        pass

hashfindings = HashFindings()

# The usage statement.
def usage():
    print """
    Basic Usage: """+paint.Y+"""./dhc.py"""+paint.N+""" [HASH]

    -----------------------------------------------------------------------------

    Keyword & Advanced Examples!

    """+paint.Y+"""./dhc.py"""+paint.N+""" [HASH] | Uses internet resources and attempts determine a hash.

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" crack bruteforce [HASH] | Attempt to BRUTEFORCE a hash through a built-in algorithm.

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" crack wordlist [HASH] [PATH-TO-WORDLIST]| Attempt to recover a hash by bruteforce with a given WORDLIST.

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" google [HASH] | query """+paint.B+"""G"""+paint.R+"""o"""+paint.Y+"""o"""+paint.B+"""g"""+paint.G+"""l"""+paint.R+"""e"""+paint.N+""" directly!

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" ping [HASH] | Check if a hash is in your session/database file.

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" hdo [HASH] | query hashes.org directly!

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" hash [PATH-TO-WORDLIST-FILE] | turn a wordlist into hash:pass pairs!

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" md5cracker [HASH] | query md5cracker directly!

                       OR

    """+paint.Y+"""./dhc.py"""+paint.N+""" load [HASHED-WORDLIST] | Recommended use is after you hash a wordlist!,
                                      load your hashed wordlist into your session/database file.

    Currently supported hash types:

    md5
    sha1
    sha224
    sha384
    sha512
    """

    print "   ", paint.R+"[WARNING!]"+paint.N+":"+paint.R+" There's a rate limit when using some internet resources, use a proxy after rate limiting kicks in."+paint.N
    print " "

# Run the program. | no class
def main():
    # The logic and all of it's pretty paint.

    #KEYWORDS = ['ping', 'google', 'crack', 'hdo', 'help', 'hash', 'monitor', 'load']

    class AutoFind():

        def FindMD5s(self):
            try:
                # md5 findings
                if len(sys.argv[1]) == 32:
                    fstarg = sys.argv[1].lower() # First arg, instead of a bunch of sys.argvs

                    print "\n" + INFO, "Trying "+paint.C+"insomnia247 [vMD5]"+paint.N+" for {}...".format(fstarg)
                    FindMd5oninsomnia247_response = hashfindings.FindMd5oninsomnia247(fstarg) # Reducing query times with variables

                    if "Error: Not a valid MD5 hash." in FindMd5oninsomnia247_response or "Hash not found." in FindMd5oninsomnia247_response:
                        print INFO, QueryFailed
                        time.sleep(1) # Much needed delay and it looks cool
                        print INFO, "Trying Leak"+paint.R+"DB"+paint.N+" for {} ...".format(fstarg)
                        time.sleep(1)

                    else:
                        time.sleep(1)
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is {0}".format(paint.C+FindMd5oninsomnia247_response)+paint.N
                        time.sleep(1)
                        databaseoperations.WriteMD5PairToFile(fstarg, FindMd5oninsomnia247_response)
                        sys.exit(0)

                    FindHashLeakDB_response = hashfindings.FindHashLeakDB(fstarg) # Reducing query times with variables

                    if FindHashLeakDB_response['found'] == "true":
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: "+paint.C+"{0}".format(FindHashLeakDB_response['hashes'][0]['plaintext'])+paint.N+""
                        time.sleep(2)
                        databaseoperations.WriteMD5PairToFile(fstarg, FindHashLeakDB_response['hashes'][0]['plaintext'])
                        sys.exit(0)


                    elif FindHashLeakDB_response['found'] == "false":
                        print INFO, QueryFailed
                        time.sleep(1)

                        print INFO, "Trying "+paint.R+"MD5"+paint.N+"DB for {} ...".format(fstarg)
                        time.sleep(1)

                    FindMD5onMD5DB_response = hashfindings.FindMD5onMD5DB(fstarg) # Reducing query times with variables

                    if FindMD5onMD5DB_response == "":
                        print INFO, QueryFailed
                        time.sleep(1)
                        print INFO, "Trying "+paint.R+"MD5"+paint.N+"Decode for {} ...".format(fstarg)
                        time.sleep(1)

                    else:
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: {0}".format(paint.C+FindMD5onMD5DB_response+paint.N)
                        time.sleep(1)
                        databaseoperations.WriteMD5PairToFile(fstarg, FindMD5onMD5DB_response)
                        sys.exit(0)

                    FindMD5onMD5DECODE_response = hashfindings.FindMD5onMD5DECODE(fstarg) # Reducing query times with variables

                    if FindMD5onMD5DECODE_response == "Not Found Go Back please":
                        time.sleep(1)
                        print INFO, QueryFailed
                        time.sleep(1)
                        print INFO, "Trying "+paint.B+"G"+paint.R+"o"+paint.Y+"o"+paint.B+"g"+paint.G+"l"+paint.R+"e"+paint.N+" for {} ...".format(fstarg)
                        time.sleep(1)

                    elif FindMD5onMD5DECODE_response == None:
                        time.sleep(1)
                        print INFO, QueryFailed
                        time.sleep(1)
                        print INFO, "Trying "+paint.B+"G"+paint.R+"o"+paint.Y+"o"+paint.B+"g"+paint.G+"l"+paint.R+"e"+paint.N+" for {} ...".format(fstarg)
                        time.sleep(1)

                    else:
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: "+paint.C+"{0}".format(FindMD5onMD5DECODE_response)+paint.N
                        time.sleep(1)
                        databaseoperations.WriteMD5PairToFile(fstarg, FindMD5onMD5DECODE_response)
                        sys.exit(0)

                    google_response = hashfindings.FindHashUsingGoogle(fstarg) # Reducing query times with variables

                    if google_response == None:
                        time.sleep(1)
                        print INFO, QueryFailed
                        time.sleep(1)
                        print INFO, "Trying "+paint.R+"MD5"+paint.N+" Cracker for {}".format(fstarg)

                    else:
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: "+paint.C+"{0}".format(google_response+paint.N)
                        time.sleep(1)
                        databaseoperations.WriteMD5PairToFile(fstarg, google_response)
                        sys.exit(0)

                    md5c_response = hashfindings.FindMD5HashOnMD5Cracker(fstarg)

                    if md5c_response["status"] == False:
                        print INFO, QueryFailed
                        time.sleep(1)
                        print INFO, "Trying sf [vMD5] for {}...".format(paint.C+fstarg+paint.N)

                    elif md5c_response["status"] == True:
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: "+paint.C+"{0}".format(md5c_response["result"]+paint.N)
                        time.sleep(1)
                        databaseoperations.WriteMD5PairToFile(fstarg, md5c_response["result"])
                        sys.exit(0)

                    sfvmd5_response = hashfindings.FindMD5onStringFunction(fstarg)

                    if sfvmd5_response == "" or sfvmd5_response == None:
                        time.sleep(1)
                        print INFO, QueryFailed
                        time.sleep(1)
                        print INFO, "All resources exhausted, done."
                        sys.exit(0)

                    elif sfvmd5_response != "" or sfvmd5_response != None:
                        time.sleep(1)
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: {}".format(sfvmd5_response)
                        databaseoperations.WriteMD5PairToFile(fstarg, sfvmd5_response)
                        sys.exit(0)

            except IndexError:
                pass # Don't display the usage statement more than once.
                #usage()

    # ------------------------------------------------------------------------------------------------------------------------------------------

        def FindSHA1s(self):
            # Sha1 findings
                try:
                    if len(sys.argv[1]) == 40:

                        print "\n" + INFO, "querying "+paint.C+"insomnia247 [vSHA1]"+paint.N+" ..."

                        if "Error: Not a valid SHA-1 hash." in hashfindings.FindSHA1insomnia247(sys.argv[1]) or "Hash not found." in hashfindings.FindSHA1insomnia247(sys.argv[1]):
                            print INFO, QueryFailed
                            time.sleep(1) # Much needed delay and it looks cool.
                            print INFO, "Trying leak"+paint.R+"db"+paint.N+" ..."
                            time.sleep(1)

                            if FindHashLeakDB(sys.argv[1])['found'] == "true":
                                print INFO, QuerySuccess
                                time.sleep(1)
                                print INFO, "Password is: "+paint.C+"{0}".format(hashfindings.FindHashLeakDB(sys.argv[1])['hashes'][0]['plaintext'])+paint.N+""

                            elif FindHashLeakDB(sys.argv[1])['found'] == "false":

                                print INFO, QueryFailed
                                time.sleep(1)

                                print INFO, "Trying "+paint.B+"G"+paint.R+"o"+paint.Y+"o"+paint.B+"g"+paint.G+"l"+paint.R+"e"+paint.N+" for {}...".format(sys.argv[1])
                                time.sleep(1)
                                google_response = utilities.Acceleration(hashfindings.FindHashUsingGoogle(sys.argv[1]))
                                if google_response == None:

                                    print INFO, QueryFailed
                                    time.sleep(1)

                                    print INFO, "Exhausted all resources, done."

                                else:
                                    print INFO, "Password is: "+paint.C+"{0}".format(google_response+paint.N), "\n"

                        else:
                            time.sleep(1)
                            print INFO, QuerySuccess
                            print INFO, "Password is "+paint.C+"{0}".format(hashfindings.FindSHA1insomnia247(sys.argv[1]))+paint.N+"", "\n"

                    elif len(sys.argv[1]) == 64 or len(sys.argv[1]) == 56 or len(sys.argv[1]) == 96 or len(sys.argv[1]) == 128:
                        print INFO, "querying Leak"+paint.R+"DB"+paint.N+" for {} ...".format(sys.argv[1])

                        if FindHashLeakDB(sys.argv[1])['found'] == "true":
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(hashfindings.FindHashLeakDB(sys.argv[1])['hashes'][0]['plaintext'])+paint.N+""

                        elif FindHashLeakDB(sys.argv[1])['found'] == "false":
                            print INFO, QueryFailed
                            time.sleep(1)
                            print INFO, "Trying "+paint.B+"G"+paint.R+"o"+paint.Y+"o"+paint.B+"g"+paint.G+"l"+paint.R+"e"+paint.N+" for {} ...".format(sys.argv[1])
                            time.sleep(1)

                except IndexError:
                    pass # Don't display the usage statement more than once.
                    #usage()

    autofind = AutoFind()
    autofind.FindMD5s()
    autofind.FindSHA1s()
# ------------------------------------------------------------------------------------------------------------------------------------------
    class KeyWords():

        ############################################################
        #                     KEYWORD/OPTIONS                      #
        ############################################################
        def Triggers(self):

            try:
                fstarg = sys.argv[1].lower()
                sndarg = sys.argv[2].lower()
                if sys.argv[1] == "crack" and sys.argv[2] == "bruteforce":

                    if len(sys.argv[3]) == 32:
                        HASHSIGN = "[MD5]:"

                    elif len(sys.argv[3]) == 40:
                        HASHSIGN = "[SHA1]:"

                    elif len(sys.argv[3]) == 64:
                        HASHSIGN = "[SHA256]:"

                    elif len(sys.argv[3]) == 96:
                        HASHSIGN = "[SHA384]:"

                    elif len(sys.argv[3]) == 128:
                        HASHSIGN = "[SHA512]:"

                    print "\n", INFO, "Attempting to crack {} {}".format(paint.R+HASHSIGN+paint.N, sys.argv[3])
                    utilities.Acceleration(hashcracking.BruteForceByAlgorithm(sys.argv[3]))

                # Attempting to recover a hash with a wordlist
                elif sys.argv[1] == "crack" and sys.argv[2] == "wordlist":
                    utilities.Acceleration(hashcracking.BruteForceByWordList(sys.argv[3]))

                # Attempting to recover a file of hashes by comparing the hash file with a wordlist
                elif sys.argv[1] == "crack" and sys.argv[2] == "hashfile":
                    utilities.Acceleration(BruteForceByCrossHashReferencingHash(sys.argv[3], sys.argv[4]))

                elif sys.argv[1] == "sf1":
                    print INFO, "Trying String Function [vSHA1] for {}...".format(paint.C+sndarg+paint.N)

                    sfvsha1_response = hashfindings.FindSHA1onStringFunction(sndarg)

                    if sfvsha1_response == "":
                        time.sleep(1)
                        print INFO, QueryFailed

                    elif sfvsha1_response != "":
                        time.sleep(1)
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: {}".format(paint.C+sfvsha1_response+paint.N)
                        databaseoperations.WriteSHA1PairToFile(sndarg, sfvsha1_response)

                # Attempting to recover a hash with Google
                elif sys.argv[1] == "google" or sys.argv[1] == "Google":
                    print "\n", INFO, "Querying "+paint.B+"G"+paint.R+"o"+paint.Y+"o"+paint.B+"g"+paint.G+"l"+paint.R+"e"+paint.N+" for "+paint.B+"{}".format(sndarg)+paint.N+" ..."
                    time.sleep(1)

                    google_response = hashfindings.FindHashUsingGoogle(sndarg)

                    if len(sndarg) == 32:

                        if google_response == None:
                            time.sleep(1)
                            print INFO, QueryFailed, "\n"
                            time.sleep(1)

                        else:
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(google_response+paint.N)
                            time.sleep(1)
                            databaseoperations.WriteMD5PairToFile(sndarg, google_response)

                    elif len(sndarg) == 40:

                        if google_response == None:
                            time.sleep(1)
                            print INFO, QueryFailed, "\n"
                            time.sleep(1)

                        else:
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(google_response+paint.N)
                            time.sleep(1)
                            databaseoperations.WriteSHA1PairToFile(sndarg, google_response)

                    elif len(sndarg) == 64:

                        if google_response == None:
                            time.sleep(1)
                            print INFO, QueryFailed, "\n"
                            time.sleep(1)

                        else:
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(google_response+paint.N)
                            time.sleep(1)
                            databaseoperations.WriteSHA256PairToFile(sndarg, google_response)

                    elif len(sndarg) == 96:

                        if google_response == None:
                            time.sleep(1)
                            print INFO, QueryFailed, "\n"
                            time.sleep(1)

                        else:
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(google_response+paint.N)
                            time.sleep(1)
                            databaseoperations.WriteSHA384PairToFile(sndarg, google_response)



                    elif len(sndarg) == 128:

                        if google_response == None:
                            time.sleep(1)
                            print INFO, QueryFailed, "\n"
                            time.sleep(1)

                        else:
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(google_response+paint.N)
                            time.sleep(1)
                            databaseoperations.WriteSHA512PairToFile(sndarg, google_response)


                # Attempting to recover a hash with by querying your session database
                elif sys.argv[1] == "ping" or sys.argv[1] == "Ping" :
                    utilities.Acceleration(databaseoperations.QueryDatabaseForSingleHash(sndarg))

                # Attempting to recover a hash by querying hashes.org
                elif sys.argv[1] == "hdo":
                    print "\n", INFO, "Trying hashes"+paint.G+"[dot]"+paint.N+"org for {} ...".format(sndarg)

                    hshsdo_repsonse = json.loads(FindHashOnHashesDotORG(sndarg))

                    if hshsdo_repsonse['found'] == False:
                        time.sleep(1)
                        print INFO, QueryFailed
                        time.sleep(1)
                        print INFO, "All resources exhausted, done."
                        sys.exit(0)

                    if hshsdo_repsonse['found'] == True:
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: "+paint.C+"{0}".format(hshsdo_repsonse['plain']+paint.N)
                        time.sleep(1)
                        databaseoperations.WriteMD5PairToFile(hshsdo_repsonse['hash'].lower(), hshsdo_repsonse['plain'])

                # Attempting to recover a hash by querying leakdb
                elif sys.argv[1] == "leakdb":

                    print "\n", INFO, "Trying Leak"+paint.R+"DB"+paint.N+" for {}...".format(paint.B+sndarg+paint.N)
                    FindHashLeakDB_response = hashfindings.FindHashLeakDB(sndarg) # Reducing query times with variables

                    if len(sndarg) == 32:

                        if FindHashLeakDB_response['found'] == "true":
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(FindHashLeakDB_response['hashes'][0]['plaintext'])+paint.N+""
                            time.sleep(2)
                            #print FindHashLeakDB_response
                            #time.sleep(2)
                            databaseoperations.WriteMD5PairToFile(sndarg, FindHashLeakDB_response['hashes'][0]['plaintext'])

                        elif FindHashLeakDB_response['found'] == "false":
                            time.sleep(1)
                            print INFO, QueryFailed, "\n"

                    if len(sndarg) == 40:

                        if FindHashLeakDB_response['found'] == "true":
                            print INFO, QuerySuccess
                            time.sleep(1)
                            print INFO, "Password is: "+paint.C+"{0}".format(FindHashLeakDB_response['hashes'][0]['plaintext'])+paint.N+""
                            time.sleep(2)
                            #print FindHashLeakDB_response
                            #time.sleep(2)
                            databaseoperations.WriteSHA1PairToFile(sndarg, FindHashLeakDB_response['hashes'][0]['plaintext'])

                        elif FindHashLeakDB_response['found'] == "false":
                            time.sleep(1)
                            print INFO, QueryFailed, "\n"


                # Attempting to recover a hash by querying md5cracker
                elif sys.argv[1] == "md5cracker":

                    print "\n", INFO, "Trying MD5 "+paint.R+"Cracker"+paint.N+" for {} ... ".format(paint.B+sndarg+paint.N)

                    md5c_response = hashfindings.FindMD5HashOnMD5Cracker(sndarg)

                    if md5c_response["status"] == False:
                        time.sleep(1)
                        print INFO, QueryFailed, "\n"
                        time.sleep(1)


                    elif md5c_response["status"] == True:
                        print INFO, QuerySuccess
                        time.sleep(1)
                        print INFO, "Password is: "+paint.C+"{0}".format(md5c_response["result"]+paint.N)
                        time.sleep(1)
                        databaseoperations.WriteMD5PairToFile(sndarg, md5c_response["result"])

                # look at the usage statement
                elif sys.argv[1] == "h" or sys.argv[1] == "help":
                    usage()

                # Load a hashed wordlist into your database
                elif sys.argv[1] == "load" or sys.argv[1] == "Load":
                    pass

                # Turn a wordlist list such ass rockyou.txt into hash:pass pairs!
                elif sys.argv[1] == "hash" or sys.argv[1] == "Hash":
                    utilities.Acceleration(fileoperations.HashAWordList())

                # Monitor a supported website for hashes, check to see if they are stored in your database and or save them for later use.
                elif sys.argv[1] == "monitor":
                    pass
                    # Monitor websites for hashes and try to find their hash/pass pairs.

                #else:
                #    print paint.R+"\n    Operation type not supported!"+paint.N
                #    usage()


            except IndexError:
                usage()

    # Instantiate classes to make the logic run.
    keywords = KeyWords() # Instantiate the keywords
    keywords.Triggers() # Trigger the keywords properly.

if __name__ == "__main__":
    # Run it all
    main()
