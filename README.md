# Distributed-Hash-Cracker
Hash recovery utility, with a database.

Designed for linux, Console based.

WARNING!
--------
This project is still under construction!

Report a bug:
-------------
https://github.com/GuerrillaWarfare/Distributed-Hash-Cracker/issues

An MD5 database (31GB Compressed), (64GB+ Un-compressed) of over 1 billion! carefully compiled cracked MD5 Hashes have been made available just for (DHC) which comes in the form of a *.session file. and should be placed in DHCs /core/database/ directory, unless you point the database within the source code elsewhere. (The link will be available when fully compressed/uploaded.)

The database will be updated accordingly, you can find annoucments about said updates via Twitter: https://twitter.com/GuerrillaWF, In time the database will be in many other hash forms as well.

For now DHC comes with two very famous pre-hashed wordlists (crack-station-human-only, rockyou.txt) ready for you to use. (2.66GB) Here: https://mega.co.nz/#!q9EkESZB!8_KbAIOHG4YE1zjMIUYDDaI0aTAaoL3_kPdZh_0NhdM

Protip:
-------
- Be sure to put all *.session files in DHCs /core/database/ directory.

Basic Usage:
------------
    -----------------------------------------------------------------------------

    Basic Usage: ./dhc.py [HASH]

    -----------------------------------------------------------------------------

    Keyword & Advanced Examples!

    ./dhc.py [HASH] | Uses internet resources and attempts determine a hash.

                       OR

    ./dhc.py crack bruteforce [HASH] | Attempt to BRUTEFORCE a hash through a built-in algorithm.

                       OR

    ./dhc.py crack wordlist [HASH] [PATH-TO-WORDLIST]| Attempt to recover a hash by bruteforce with a given WORDLIST.

                       OR

    ./dhc.py google [HASH] | query Google directly!

                       OR

    ./dhc.py ping [HASH] | Check if a hash is in your session/database file.

                       OR

    ./dhc.py hdo [HASH] | query hashes.org directly!

                       OR

    ./dhc.py hash [PATH-TO-WORDLIST-FILE] | turn a wordlist into hash:pass pairs!

                       OR

    ./dhc.py md5cracker [HASH] | query md5cracker directly!

                       OR

    ./dhc.py load [HASHED-WORDLIST] | Recommended use is after you hash a wordlist!,
                                      load your hashed wordlist into your session/database file.

    Currently supported hash types:

    md5
    sha1
    sha224
    sha384
    sha512

Guerrilla Warfare Free License ("GWFL"):

1. You're free to modify this software to YOUR liking or leave it as is.

2. This software comes as is, and may or may not receive any additional updates, Contact the developer for more help.

3. The initial download and use of this software constitutes that you adhere and comply to the writing of this end user license agreement (EULA).

4. The Developer is NOT at ALL under any circumstances responsible for YOUR actions or the actions of any other third part instances that may use this software for any illegal or nefarious activities.
