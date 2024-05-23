"""
Copyright© 29/02/2024, Maxime Gaucher MSI E Cybersecurite 2024
Version: 6.0
Project
"""

import csv
import paramiko
import requests
from requests.auth import HTTPBasicAuth

def ssh_connect_single(hostname, username, password):
    """
    Connects to a machine via SSH with a single username/password pair.
    """
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Attempt to connect with the provided username and password
        ssh_client.connect(hostname, username=username, password=password)
        print("Connection successful")
        # Perform tasks here if connection is successful
        ssh_client.close()
        return True
    except paramiko.AuthenticationException:
        print("Authentication failed")
        return False
    except Exception as e:
        print(f"Error during connection: {e}")
        return False

def ssh_connect_multiple(hostname, credentials_list):
    """
    Connects to a machine via SSH with a list of username/password pairs.
    """
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for credentials in credentials_list:
        username, password = credentials
        try:
            ssh_client.connect(hostname, username=username, password=password)
            print(f"Connection successful with {username}/{password}")
            ssh_client.close()
            return True  # Stop if a connection is successful
        except paramiko.AuthenticationException:
            print(f"Authentication failed with {username}/{password}")
        except Exception as e:
            print(f"Error during connection with {username}/{password}: {e}")

    return False  # Return False if no pair succeeded


def http_connect_single(url, username, password):
    """
    Connects to an HTTP service with a single username/password pair.
    """
    try:
        # Attempt to connect with the provided URL, username, and password
        response = requests.get(url, auth=HTTPBasicAuth(username, password))

        if response.status_code == 200:
            print("Connection successful")
            return True
        else:
            print(f"Connection failed with status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error during connection: {e}")
        return False

def http_connect_multiple(url, credentials_list):
    """
    Connects to an HTTP service with a list of username/password pairs.
    """
    for credentials in credentials_list:
        username, password = credentials
        try:
            # Attempt to connect with the provided URL, username, and password
            response = requests.get(url, auth=HTTPBasicAuth(username, password))

            if response.status_code == 200:
                print(f"Connection successful with {username}/{password}")
                return True
            else:
                print(f"Connection failed with {username}/{password}, status {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error during connection with {username}/{password}: {e}")

    return False  # Return False if no pair succeeded


def add_line_csv_authen(filename, line):
    """
    Adds a new line to a CSV file.
    """
    # Open the CSV file in append mode and write the new line
    with open(filename, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(line)
