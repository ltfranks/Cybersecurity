import bcrypt
from nltk.corpus import words

# Load the list of potential passwords between 6 and 10 characters long
potential_passwords = [word for word in words.words() if 6 <= len(word) <= 10]


# Extracting the necessary components from a hash line
def extract_hash_components(hash_line):
    parts = hash_line.split('$')
    # don't need parts[0] bec its just username
    algorithm = parts[1]
    workfactor = parts[2]
    salt = parts[3][:22]  # First 22 characters are the salt
    full_salt = f"${algorithm}${workfactor}${salt}"  # Recreate the full salt
    hash_value = parts[3][22:]  # Rest is the hash
    return full_salt, hash_value


# Cracking a single hash
def crack_hash(full_salt, hash_value):
    for password in potential_passwords:
        hashed = bcrypt.hashpw(password.encode('utf-8'), full_salt.encode('utf-8'))
        # comparing string from corpus and shadow.txt
        if hashed.decode('utf-8') == f"{full_salt}{hash_value}":
            return password
    return None


# Load the shadow file and attempting to crack each hash
with open('shadow.txt', 'r') as file:
    for line in file:
        username, user_hash = line.strip().split(':')
        # python returns full_salt and hash_value
        full_salt, hash_value = extract_hash_components(user_hash)
        password = crack_hash(full_salt, hash_value)
        if password:
            print(f"Cracked password for {username}: {password}")
        else:
            print(f"Failed to crack password for {username}")

