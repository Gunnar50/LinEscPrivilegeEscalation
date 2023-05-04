#!/usr/bin/env python3
import os
from Scripts.settings import *

"""
This script walks through the directory tree starting at the root directory (/) and looks for files
that are world-writable. It checks the write permission of the file using the os.access() function
with the os.W_OK flag, and it checks that the file is not executable by checking the execute permission
using the os.X_OK flag. If a file is found that is world-writable, it is printed to the console.
"""

progress = Progress()


def result_world_writable_files(silence, shell_users):
    # Define the directory to search for world-writable files
    directory = '/'

    wwf_list = []
    # Walk through the directory tree and find world-writable files
    for root, dirs, files in os.walk(directory):
        for name in files:
            # Get the full path of the file
            filepath = os.path.join(root, name)

            # Check if the file is world-writable
            for user in shell_users:
                if os.access(filepath, os.W_OK) and not os.access(filepath, os.X_OK) and user in filepath:
                    wwf_list.append((filepath, "This path can be used by any user."))

    progress.running = False

    if len(wwf_list) > 0:
        output("<p>World-writable path/files found. Worth taking a second look.</p>", True)
        if not silence:
            output(end="\r")
            output(YELLOW + "World-writable path/files found. Worth taking a second look.\n")
            for filepath in wwf_list:
                output(RED + filepath[0] + END)
    else:
        if not silence:
            output(GREEN + "No World-writable files or directories found!" + END)

    return wwf_list


def find_world_writable_files(silence, shell_users):
    progress_thread = CThread(target=lambda: progress.progress_func(silence))
    result_findings_thread = CThread(target=lambda: result_world_writable_files(silence, shell_users))

    progress_thread.start()
    result_findings_thread.start()

    progress_thread.join()
    return result_findings_thread.join()
