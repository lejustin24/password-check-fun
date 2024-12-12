import re
import math

# Sample dictionary of common weak passwords
# https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
COMMON_PASSWORDS = {
    "123456", "12345", "qwerty", "password", "12345678", "111111", "123123",
    "1234567890", "1234567", "qwerty123", "000000", "1q2w3e", "aa12345678",
    "abc123", "password1", "1234", "qwertyuiop", "123321", "password123",
    "123456789", "football", "1111111", "Iloveyou", "1q2w3e4r5t", "Qwertyuiop",
    "123", "Monkey", "Dragon", "987654321", "mynoob", "666666", "18atcskd2w",
    "7777777", "1q2w3e4r", "654321", "555555", "3rjs1la7qe", "google",
    "123qwe", "zxcvbnm", "monkey", "letmein", "dragon1234", "baseball",
    "sunshine", "iloveyou", "trustno1", "princess", "adobe123", "welcome",
    "login", "admin", "solomonkey", "q2w3e4r", "master", "photoshop", "qaz2wsx",
    "ashley", "bailey", "passw0rd", "shadow", "michaellogin", "jesus", "superman",
    "qazwsx", "ninja", "azerty", "sololoveme", "whatever", "donald",
    "batman", "zaq1", "zaq1qazwsx", "password1000000", "starwars",
    "qwerty123123", "qwe", "mustang", "121212", "football654321",
    "flower123", "123123123", "555555", "lovely", "6543217777777",
    "!@#$%^&*", "hello", "charlie888888", "696969", "hottie", "freedomaa",
    "1231234567", "123123123555555", "passw0rddragon", "passw0rd654321",
    "welcome21", "888888", "qwertyuiophottie", "lmeindragon", "7777777"
}


def calculate_entropy(password):
    # Entropy calculation based on character variety and length
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26  # Lowercase
    if re.search(r"[A-Z]", password):
        pool_size += 26  # Uppercase
    if re.search(r"\d", password):
        pool_size += 10  # Digits
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        pool_size += 33  # Special symbols
    if re.search(r"\s", password):
        pool_size += 1  # Whitespace (if allowed, though disallowed in this checker)

    # Entropy = log2(pool_size^length)
    if pool_size == 0:  # No valid characters
        return 0
    return len(password) * math.log2(pool_size)

def check_password_strength(password):
    # Strong password criteria
    length_error = len(password) < 8  # Minimum length of 8
    numeric_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None
    whitespace_error = re.search(r"\s", password) is not None  # No spaces allowed
    repeat_error = len(password) != len(set(password))  # No repeated characters
    dictionary_error = password.lower() in COMMON_PASSWORDS  # Matches common passwords
    entropy_error = calculate_entropy(password) < 60  # Minimum entropy threshold

    password_ok = not (
        length_error or numeric_error or uppercase_error or 
        lowercase_error or symbol_error or whitespace_error or 
        repeat_error or dictionary_error or entropy_error
    )
    
    return {
        'Password is strong': password_ok,
        'Too short': length_error,
        'No numerics': numeric_error,
        'No uppercase letters': uppercase_error,
        'No lowercase letters': lowercase_error,
        'No symbols': symbol_error,
        'Contains whitespace': whitespace_error,
        'Repeated characters': repeat_error,
        'Matches common passwords': dictionary_error,
        'Low entropy': entropy_error,
    }

if __name__ == "__main__":
    password = input("Enter a password to check: ")
    result = check_password_strength(password)

    print("\nPASSWORD CHECK RESULTS")
    for key, value in result.items():
        if key == 'Password is strong':
            print(f"{key}: {'Yes' if value else 'No'}")
        else:
            print(f"{key}: {'Yes' if value else 'No'}")
