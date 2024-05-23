"""
Copyright© 29/02/2024, Maxime Gaucher MSI E Cybersecurite 2024
Verison : 6.0
Projet
"""

from affichage_menu import Display_menu_title, Display_menu_options, Display_menu_optionScan, Display_menu_exploit, Display_menu_password, Display_menu_authentication, Display_menu_exploit_vuln, Display_menu_post_exploit
from colorama import init

# Import modules for different functionalities
# Scanning module
from modules.scan_ip_os import scan_addressing
from modules.portscan import Scan_Nmap, Scan_Nmap_Choice

# Vulnerability Detection module
from modules.searchsploit import search_exploit
from modules.scan_vulnerable_proto import scan_and_analyze_ports
from modules.scan_vulnerable_os import scan_and_analyze_os

# Security Analysis module
from modules.eval_password import evaluate_pwd_strength, evaluate_csv_passwords, add_line_to_csv_passwords

# Authentication Analysis module
from modules.Connection import ssh_connect_single, ssh_connect_multiple, http_connect_single, http_connect_multiple, add_line_csv_authen

# Vulnerability Exploitation module
from modules.keys_certif import scan_ssh_keys_windows, scan_ssh_keys_linux, scan_certificates_windows, scan_certificates_linux, detect_os

# Post Exploitation module
from modules.extract_ad import detect_active_directory, extract_ad_tree

# Report Creation module
from modules.gen_pdf import generate_security_report


if __name__ == "__main__":

    init()  # Initialize colorama for colored terminal output
    Display_menu_title()  # Display the menu title
    Display_menu_options()  # Display the main menu options
    
    option = int(input(">>> Choose an option\n>>> "))  # Read user's main menu choice

    while option != 99:  # Loop until the user chooses to exit

        if option == 1:  # If the user chooses Scanning
            Display_menu_optionScan()  # Display scanning submenu options
            subOption = str(input(">>> Choose an option\n>>> "))  # Read user's scanning submenu choice
            while subOption != 'z':  # Loop until the user chooses to go back

                if subOption == 'a':  # If the user chooses Network / OS Scan
                    target_ip = input("Enter the IP address of the network to scan (ex: 192.168.1.0/24) : ")
                    scan_addressing(target_ip)

                if subOption == 'b':  # If the user chooses Port Scan
                    TARGET = str(input(">>> Type target domain or IP\n>>> "))
                    scan, version = Scan_Nmap(TARGET)
                    print(scan)

                if subOption == 'c':  # If the user chooses Custom Port Scan
                    TARGET = str(input(">>> Type target domain or IP\n>>> "))
                    f_port = str(input(">>> The first port of range\n>>> "))
                    l_port = str(input(">>> The last port of range\n>>> "))
                    scan, version = Scan_Nmap_Choice(TARGET, f_port, l_port)
                    print(scan)

                Display_menu_optionScan()  # Display scanning submenu options again
                subOption = str(input(">>> Choose an option\n>>> "))  # Read user's scanning submenu choice


        elif option == 2:  # If the user chooses Detection Vulnerabilities
            Display_menu_exploit()  # Display vulnerability detection submenu options
            subOption = str(input(">>> Choose an option\n>>> "))  # Read user's vulnerability detection submenu choice
            while subOption != 'z':  # Loop until the user chooses to go back

                if subOption == 'a':  # If the user chooses to search for vulnerabilities on a service
                    service = str(input(">>> Search for exploits on a service (ex: wordpress 4.0)\n>>> "))
                    exploit = search_exploit(service)
                    print(exploit)

                if subOption == 'b':  # If the user chooses to search for vulnerabilities on a protocol
                    ip_proto = str(input(">>> Choose the machine you want to scan (by IP)\n>>> "))
                    nb_ports_proto = str(input(">>> Choose the ports you want to scan (by ports, ex:1-50)\n>>> "))
                    result_vuln_proto = scan_and_analyze_ports(ip_proto, nb_ports_proto)
                    print(result_vuln_proto)

                if subOption == 'c':  # If the user chooses to search for vulnerabilities on an OS
                    ip_os = str(input(">>> Choose the machine or range you want to scan (by IP or range, ex 192.168.1.1 or 192.168.1.1-50)\n>>> "))
                    result_vuln_os = scan_and_analyze_os(ip_os)
                    print(result_vuln_os)

                
                Display_menu_exploit()  # Display vulnerability detection submenu options again
                subOption = str(input(">>> Choose an option\n>>> "))  # Read user's vulnerability detection submenu choice
        

        elif option == 3:  # If the user chooses Security Analysis
            Display_menu_password()  # Display password analysis submenu options
            subOption = str(input(">>> Choose an option\n>>> "))  # Read user's password analysis submenu choice
            while subOption != 'z':  # Loop until the user chooses to go back

                if subOption == 'a':  # If the user chooses to test a password
                    password = input("Enter the password to test: ")
                    difficulty = evaluate_pwd_strength(password)
                    print("Password difficulty:", difficulty)

                if subOption == 'b':  # If the user chooses to test passwords from a CSV list
                    csv_file_path = "modules\words_keys.csv"
                    results = evaluate_csv_passwords(csv_file_path)
                    for login, password, difficulty in results:
                        print(f"Login: {login}, Password: {password}, Difficulty: {difficulty}")

                if subOption == 'c':  # If the user chooses to add a password to the CSV file
                    new_password_pass = input("Enter the new password : ")
                    new_line_password = [new_password_pass]
                    name_file_csv = "modules\words_keys.csv"
                    add_line_to_csv_passwords(name_file_csv, new_line_password)
                    
                Display_menu_password()  # Display password analysis submenu options again
                subOption = str(input(">>> Choose an option\n>>> "))  # Read user's password analysis submenu choice


        elif option == 4:  # If the user chooses Authentication Password Analysis
            Display_menu_authentication()  # Display authentication analysis submenu options
            subOption = str(input(">>> Choose an option\n>>> "))  # Read user's authentication analysis submenu choice
            while subOption != 'z':  # Loop until the user chooses to go back

                if subOption == 'a':  # If the user chooses simple SSH authentication
                    host_connection_ssh_s = input("Enter the IP of the machine you want to connect to: ")
                    login_connection_ssh_s = input("Enter the authentication login: ")
                    password_connection_ssh_s = input("Enter the authentication password: ")
                    ssh_connect_single(host_connection_ssh_s, login_connection_ssh_s, password_connection_ssh_s)

                if subOption == 'b':  # If the user chooses multi-factor SSH authentication
                    host_connection_ssh_m = input("Enter the IP of the machine you want to connect to: ")
                    file_authen = "modules\logins_authen.csv"
                    ssh_connect_multiple(host_connection_ssh_m, file_authen)

                if subOption == 'c':  # If the user chooses simple HTTP authentication
                    url_connection_http_s = input("Enter the URL of the authentication page: ")
                    login_connection_http_s = input("Enter the authentication login: ")
                    password_connection_http_s = input("Enter the authentication password: ")
                    http_connect_single(url_connection_http_s, login_connection_http_s, password_connection_http_s)

                if subOption == 'd':  # If the user chooses multi-factor HTTP authentication
                    url_connection_ssh_m = input("Enter the IP of the machine you want to connect to: ")
                    file_authen = "modules\logins_authen.csv"
                    http_connect_multiple(url_connection_ssh_m, file_authen)
                
                if subOption == 'e':  # If the user chooses to add an authentication line to CSV
                    new_login_authen = input("Enter the new login : ")
                    new_password_authen = input("Enter the new password : ")
                    new_line_authen = [new_login_authen, new_password_authen]
                    name_file2_csv = "modules\logins_authen.csv"
                    add_line_csv_authen(name_file2_csv, new_line_authen)
                    
                Display_menu_authentication()  # Display authentication analysis submenu options again
                subOption = str(input(">>> Choose an option\n>>> "))  # Read user's authentication analysis submenu choice


        elif option == 5:  # If the user chooses Exploitation of Vulnerabilities
            Display_menu_exploit_vuln()  # Display exploitation vulnerabilities submenu options
            subOption = str(input(">>> Choose an option\n>>> "))  # Read user's exploitation vulnerabilities submenu choice
            while subOption != 'z':  # Loop until the user chooses to go back

                if subOption == 'a':  # If the user chooses to retrieve authentication keys
                    
                    # Information about the remote machine
                    ip_exploit = input("Enter the IP of the machine you want to connect to: ")
                    username_exploit = input("Enter the authentication login: ")
                    password_exploit = input("Enter the authentication password: ")
                    
                    # Detect the type of operating system
                    os_type = detect_os(ip_exploit, username_exploit, password_exploit)
                    
                    print(f"The detected operating system is: {os_type}")
                    
                    # Execute operations according to the detected operating system
                    if os_type == "Windows":
                        scan_ssh_keys_windows(ip_exploit, username_exploit, password_exploit)

                    elif os_type == "Linux" or os_type == "macOS":
                        scan_ssh_keys_linux(ip_exploit, username_exploit, password_exploit)

                    else:
                        print("Unrecognized operating system. Unable to proceed.")                                  

                if subOption == 'b':  # If the user chooses to retrieve certificates

                    # Information about the remote machine
                    ip_exploit = input("Enter the IP of the machine you want to connect to: ")
                    username_exploit = input("Enter the authentication login: ")
                    password_exploit = input("Enter the authentication password: ")
                    
                    # Detect the type of operating system
                    os_type = detect_os(ip_exploit, username_exploit, password_exploit)
                    
                    print(f"The detected operating system is: {os_type}")
                    
                    # Execute operations according to the detected operating system
                    if os_type == "Windows":
                        scan_certificates_windows(ip_exploit, username_exploit, password_exploit)

                    elif os_type == "Linux" or os_type == "macOS":
                        scan_certificates_linux(ip_exploit, username_exploit, password_exploit)

                    else:
                        print("Unrecognized operating system. Unable to proceed.")
                    
                Display_menu_exploit_vuln()  # Display exploitation vulnerabilities submenu options again
                subOption = str(input(">>> Choose an option\n>>> "))  # Read user's exploitation vulnerabilities submenu choice


        elif option == 6:  # If the user chooses Post Exploitation
            Display_menu_post_exploit()  # Display post exploitation submenu options
            subOption = str(input(">>> Choose an option\n>>> "))  # Read user's post exploitation submenu choice
            while subOption != 'z':  # Loop until the user chooses to go back

                if subOption == 'a':  # If the user chooses to detect and extract Active Directory data
                        
                    # Information about the remote machine
                    ip_ad = input("Enter the IP of the machine you want to connect to: ")
                    username_ad = input("Enter the authentication login: ")
                    password_ad = input("Enter the authentication password: ")
                        
                    # Check if Active Directory service is present
                    ad_present = detect_active_directory(ip_ad, username_ad, password_ad)
                        
                    if ad_present:
                        print("Active Directory service detected.")
                        # Extract AD tree
                        extract_ad_tree(ip_ad, username_ad, password_ad)
                    else:
                        print("Active Directory service not detected.")                              
                        
                Display_menu_post_exploit()  # Display post exploitation submenu options again
                subOption = str(input(">>> Choose an option\n>>> "))  # Read user's post exploitation submenu choice
        
        elif option == 7:  # If the user chooses Report Creation
            rapport_ip = input("Enter the IP address of the network to scan (ex: 192.168.1.0/24) : ")
            generate_security_report(rapport_ip)  # Generate the security report

        Display_menu_options()  # Display the main menu options again
        option = int(input(">>> Choose an option\n>>> "))  # Read user's main menu choice





