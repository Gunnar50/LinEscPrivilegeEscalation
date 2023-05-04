#!/usr/bin/python3

import os
from bs4 import BeautifulSoup
import requests
from gtfobins_database import database_dict


suid_list = [key for key, value in database_dict.items() if len(value[1]) > 0]


def suid():
    for bin_name in suid_list:
        which_cmd = os.popen(f"which {bin_name}").read()
        if which_cmd:
            os.system(f"chmod +s {which_cmd}")
            # os.system(f"chmod -s {which_cmd}")
        # if bin_name == "cpio":
        #     break


def cap():
    cap_list = ["gdb", "node", "perl", "php", "python", "ruby", "rview", "rvim", "view", "vim", "vimdiff"]
    for cap in cap_list:
        which = os.popen(f"which {cap}").read()
        if which:
            os.system(f"cp {which.strip()} .")
            os.system(f"setcap cap_setuid+ep {cap}")
        # os.system(f"rm {cap}")


# suid()
cap()



