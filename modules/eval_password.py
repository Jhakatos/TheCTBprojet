"""
Copyright© 29/02/2024, Maxime Gaucher MSI E Cybersecurite 2024
Version: 6.0
Project
"""

import string
import csv

def evaluate_pwd_strength(password):
    """Evaluates the strength of a password based on its length and complexity.

    Args:
        password (str): The password to evaluate.

    Returns:
        str: A message indicating the strength of the password.
    """
    length = len(password)
    strength = 0
    
    # Check for the presence of lowercase, uppercase, digits, and special characters
    if any(c.islower() for c in password):
        strength += 1
    if any(c.isupper() for c in password):
        strength += 1
    if any(c.isdigit() for c in password):
        strength += 1
    if any(c in string.punctuation for c in password):
        strength += 1
    
    # Check if the password is common by comparing it to a list of common passwords
    common_pwd = False
    pwd_file = 'modules/logins'
    with open(pwd_file, 'r') as f:
        words = f.read().splitlines()
        if password.lower() in words:
            common_pwd = True

    score = length + strength
    
    # Evaluate the strength of the password based on the calculated score
    if common_pwd:
        return "Very Weak - Common password"
    elif score < 6:
        return "Very Weak"
    elif score < 10:
        return "Weak"
    elif score < 15:
        return "Average"
    elif score < 20:
        return "Good"
    else:
        return "Very Good"

def evaluate_csv_passwords(logins):
    """Evaluates the strength of passwords in a CSV file.

    Args:
        logins (str): The path to the CSV file containing usernames and passwords.

    Returns:
        list: A list of tuples containing the username, password, and its strength.
    """
    difficulties = []
    with open(logins, newline='') as csvfile:
        csv_reader = csv.reader(csvfile)
        for line in csv_reader:
            if len(line) == 2:
                username, password = line
                difficulty = evaluate_pwd_strength(password)
                difficulties.append((username, password, difficulty))
            else:
                print("The line does not contain two elements.")
    return difficulties

def add_line_to_csv_passwords(csv_file, line):
    """Adds a line to the CSV file containing usernames and passwords.

    Args:
        csv_file (str): The path to the CSV file.
        line (tuple): The tuple containing the username and password to add.
    """
    with open(csv_file, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(line)
