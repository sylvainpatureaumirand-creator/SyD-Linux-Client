SyD - Client Linux v1.0

SyD est une application cliente sécurisée qui utilise OpenSSL et GMP pour chiffrer localement les données. Ce guide vous accompagne dans l’installation des dépendances, la configuration, la compilation et la validation mémoire sur une distribution Debian.

Installation des dépendances

Commencez par mettre à jour votre système puis installez le compilateur et les librairies nécessaires avec ces commandes :

sudo apt update

sudo apt install build-essential libssl-dev libgmp-dev

Préparation des répertoires et fichiers de configuration

Créez les dossiers de configuration et de base de données :

mkdir ./conf/ ./bdd

echo '{ "SAFE":"JemetsLAclefquivaêtresuperduraretenir!!!" }' > ./conf/Client.cfg

Ensuite, créez les fichiers de configuration serveur ServerSYD.cfg et ServerProvider.cfg contenant les paramètres uuid, IP et PORT (le uuid est optionnel pour le Provider) :

echo '{ "uuid":"853896a6-5ddb-4d0b-9516-52fc46cbe9b6", "IP":"82.67.97.63", "PORT":"5110" }' > ./conf/ServerSYD.cfg

echo '{ "uuid":"", "IP":"82.67.97.63", "PORT":"5120" }' > ./conf/ServerProvider.cfg

Ajoutez le certificat de l'autorité racine des serveurs dans conf/SYD-rootCA-PP.pem

-----BEGIN CERTIFICATE-----
MIICMTCCAdegAwIBAgIUJ1A2cXjdqBUNTHKG1OPDACByzXMwCgYIKoZIzj0EAwIw
bjELMAkGA1UEBhMCRlIxFjAUBgNVBAgMDUlsZS1kZS1GcmFuY2UxDjAMBgNVBAcM
BVBhcmlzMRAwDgYDVQQKDAdTeVBhTWlyMQ8wDQYDVQQLDAZTWUQtUFAxFDASBgNV
BAMMC1NZRC1Sb290LUNBMB4XDTI1MDMyNTA4NTc0MVoXDTM1MDMyMzA4NTc0MVow
bjELMAkGA1UEBhMCRlIxFjAUBgNVBAgMDUlsZS1kZS1GcmFuY2UxDjAMBgNVBAcM
BVBhcmlzMRAwDgYDVQQKDAdTeVBhTWlyMQ8wDQYDVQQLDAZTWUQtUFAxFDASBgNV
BAMMC1NZRC1Sb290LUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4pF64CJC
7pFIFEpZtP16s2Ut4eWJJkDsFYAUJ+uYBjLXiHb0Lr7FIUn32MhYJ3YjbGAaxZL1
AUbUqtmLppQ8FaNTMFEwHQYDVR0OBBYEFL909BhGd2Cispy1erFElYb7LyKIMB8G
A1UdIwQYMBaAFL909BhGd2Cispy1erFElYb7LyKIMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSAAwRQIgNyfd8wqm9GxRY5gXA7cOjKMtNcv/7LmOr/hrO2w3
WXECIQCXbmBOql9BeccM6JJ+Fy45/6IG/quXXP1aRq2ZWm7MGw==
-----END CERTIFICATE-----


Compilation

Compilez le client avec les options de compilation sécurisées suivantes :

gcc -Wall -Wextra -Werror -Wformat -Wformat-security -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2 Linux-client-v0.9.c -o SyD -lssl -lcrypto -lgmp

Validation mémoire avec Valgrind

Pour vérifier l’absence de fuites mémoire, exécutez les tests suivants selon les différentes options du client. Les logs seront enregistrés dans un fichier texte.

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.9.txt ./SyD -i

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.9.txt ./SyD -s

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.9.txt ./SyD -a ./Testv0.9.syd

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.9.txt ./SyD -c ./Testv0.9.syd log.debug

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.9.txt ./SyD -u ./Testv0.9.syd .

Licence

Ce projet est distribué sous licence GNU GPL v3


Pour toute question ou contribution : sylvain.patureau.mirand@gmail.com
