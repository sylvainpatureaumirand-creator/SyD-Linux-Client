SyD - Client Linux v0.9

SyD est une application cliente sécurisée qui utilise OpenSSL et GMP pour chiffrer localement les données. Ce guide vous accompagne dans l’installation des dépendances, la configuration, la compilation et la validation mémoire sur une distribution Debian.

Installation des dépendances

Commencez par mettre à jour votre système puis installez le compilateur et les librairies nécessaires avec ces commandes :

sudo apt update

sudo apt install build-essential libssl-dev libgmp-dev

Préparation des répertoires et fichiers de configuration

Créez les dossiers de configuration et de base de données :

mkdir ./conf/ ./bdd

echo '{ "SAFE":"Tirelipimponsurlechihuahua!!!" }' > ./conf/Client.cfg

Ensuite, créez les fichiers de configuration serveur ServerSYD.cfg et ServerProvider.cfg contenant les paramètres uuid, IP et PORT (le uuid est optionnel pour le Provider) :

echo '{ "uuid":"c25f250d-2867-48e9-9553-1734de7c46c3", "IP":"192.168.1.224", "PORT":"443" }' > ./conf/ServerSYD.cfg

echo '{ "uuid":"", "IP":"192.168.1.225", "PORT":"443" }' > ./conf/ServerProvider.cfg

Ajoutez le certificat de l'autorité racine des serveurs dans conf/SYD-rootCA-PP.pem

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
