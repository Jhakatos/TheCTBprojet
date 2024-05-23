### Projet fin d'année MSI-1 E Cybersécurité - Création Tool Box ###
----------------------------------------------------------------------
  
# Objectif : 
Développement d'une boîte à outils interactive et automatisée conçue dans le but de simplifier et d'automatiser les processus de tests d'intrusion, notamment les Pentests.


# Installation des pré-requis : 
  
La Tool Box : Cyber Tool Box; Nécessite pour son utilisation quelques pré requis.

- L'installation de pyhton sur le site oficiel de Python : https://www.python.org/ftp/python/3.12.3/python-3.12.3-amd64.exe

- Pour l'installation des différentes bibliotèques de Python, vous pouvez utilisé le fichier d'installation  .bat pour téléchargerle toutes les bibliotèques (Pour cela, lors de l'installation de Pyhton il faut bien cocher la case, pour que python soit bien ajouter au path du système, et permet l'éxécution du  .bat)

- L'installationd de l'application Nmap, car dans notre tool box nous utilisons la bibliotèque Nmap affilier à Pyhton, et nécessite l'installation de l'application pour son bon fonctionnement.
  

## Utilisation de la toolbox :
  
Pour initier l'utilisation de notre boîte à outils, il vous suffira simplement d'exécuter le fichier principal "cyber-tool-box.py". Cette action lancera l'outil et vous dirigera instantanément vers notre menu principal, où vous pourrez explorer les différentes fonctionnalités à votre disposition.

Ensuite, la navigation au sein de notre boîte à outils s'effectue intuitivement, vous permettant de choisir les outils en fonction de vos besoins spécifiques et du type de tâches que vous entreprenez.

Je tiens à souligner que bien que nos commentaires soient en français pour faciliter la compréhension du code, nous avons décidé d'adopter l'anglais pour l'interface utilisateur et le développement du code. Cette approche permet une meilleure accessibilité et une compatibilité plus large avec les normes de l'industrie.

Notre boîte à outils est conçue selon une architecture pensée et organisée, où chaque outil est soigneusement catégorisé et classifié, facilitant ainsi votre exploration et votre utilisation efficace de notre gamme complète d'outils de sécurité. 
  
Cyber Tool Box :  
  Scanning :
     - Network / OS Scan
     - Port Scan (21 - 433)
     - Custom Port Scan 

  Detection Vulnerabilities :
     - Search for vulnerabilities and exploits on a service
     - Search for vulnerabilities on a protocol
     - Search for vulnerabilities on an OS

  Security Analysis
     - Test password
     - CSV password list
     - Add line to CSV file

  Authentication Password Analysis
     - Simple SSH Authentication
     - Multi-Factor SSH Authentication
     - Simple HTTP Authentication
     - Multi-Factor HTTP Authentication
     - Add line to CSV file

  Exploitation of Vulnerabilities
     - Retrieve authentication keys
     - Retrieve certificates

  Post Exploitation
     - Detect an AD service and retrieve a CSV file of the domain's users and machine tree

  Report Creation

