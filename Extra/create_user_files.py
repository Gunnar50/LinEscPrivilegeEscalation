import os
import subprocess
import random
import string

# Customize these values as needed
num_users = 50
num_files_per_user = 100
min_file_size = 1  # In KB
max_file_size = 100  # In KB


# Function to generate random strings
def random_string(length):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))


# Create users
for i in range(num_users):
    username = f'user{i}'
    password = random_string(8)

    # Create the user account
    subprocess.run(['useradd', '-m', '-p', password, username], check=True)

    # Create files and directories for each user
    user_home = f'/home/{username}'
    for j in range(num_files_per_user):
        file_name = f'{user_home}/{random_string(10)}.txt'
        # Generate random file content
        file_size = random.randint(min_file_size, max_file_size) * 1024
        file_content = random_string(file_size)

        # Write file content to the file
        with open(file_name, 'w') as f:
            f.write(file_content)

        # Set the file owner to the user
        subprocess.run(['chown', username, file_name], check=True)

    # Print progress
    print(f'Created user {username} and {num_files_per_user} files.')
