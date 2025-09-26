/*
 * Copyright (C) 2025 Sylvain <ton.email@exemple.com>
 *
 * This file is part of SyD.
 *
 * SyD is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SyD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SyD.  If not, see <https://www.gnu.org/licenses/>.
*/ 

/*
#Installer les librairies et le compilateur sur Debian
sudo apt update
sudo apt install build-essential libssl-dev libgmp-dev

#Créer les repertoiress conf et bdd
mkdir ./conf/ ./bdd

#Créer un fichier Client.cfg avec une balise SAFE qui contient une chaine de caractère qui sert a chiffrer la BDD locale
echo "{ \n \"SAFE\":\"Tirelipimponsurlechihuahua!!!\" \n}"  ./conf/Client.cfg 
#Créer les fichiers de configuration ServerSYD.cfg ServerProvider.cfg dans lequel la balise uuid, IP et PORT sont présent (uuid optionnel pour le SP)
echo "{ \n \"uuid\":\"c25f250d-2867-48e9-9553-1734de7c46c3\",\n  \"IP\":\"192.168.1.224\",\n  \"PORT\":\"443\",}"  ./conf/ServerSYD.cfg 
echo "{ \n \"uuid\":\"\",\n  \"IP\":\"192.168.1.225\",\n  \"PORT\":\"443\",}"  ./conf/ServerProvider.cfg 

#Compilation
gcc -Wall -Wextra -Werror -Wformat -Wformat-security -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2 Linux-client-v0.7.c -o SyD -lssl -lcrypto -lgmp 

#Validation de la conformité mémoire
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.7.txt ./SyD -i
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.7.txt ./SyD -s
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.7.txt ./SyD -a ./Testv0.7.syd
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.7.txt ./SyD -c ./Testv0.7.syd log.debug
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -v --log-file=./Valgrind-Linux-client-c-v0.7.txt ./SyD -u ./Testv0.7.syd .
*/

//------------------------------------------------------------------------------//
// Liste des librairies
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h> // size_t
#include <unistd.h> // Readlink
#include <regex.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <gmp.h>

// Définition globales
#define MAX_FILES 100
#define MAX_FILENAME_LEN 260
#define MAX_FILENAME_PATH_LEN 520
#define MAX_FILES_SIZE 52428800 // fixe la taille des archives .syd traitées
#define MAX_FILES_SIZE_30P 68157440 // fixe la taille du buffer pour traiter les archives
#define MAX_HTTP_RQST_SIZE 1024

// définition des tailles de valeur des variables
#define CANARY_VALUE 0xDEADBEEF
#define SIZE 1024 // doit être 260 Octets plus grand que SIZE_P
#define SIZE_X 256 //Max 512 char (dépend du SYD et du SP)
#define SIZE_P 512 //Max 2485 char (dépend du SYD et du SP)
#define SIZE_BUFFER 16500 // Valeur Max 16384 traitées

//------------------------------------------------------------------------------//
// Declaration des structures

// Structures pour la lecture des paramètre du programme
struct ProgParams {
    size_t entry_number;
    char **values;
};

// Structures pour la lecture des JSON
struct JsonEntry {
    char *key;
    char *value;
};

struct JsonValues {
    struct JsonEntry *entries;
    size_t entry_count;
};

// Structure pour contenir les constantes du JSON de communications
struct SYD {
    char uuid[40];
    char g[SIZE_BUFFER];
    char p[SIZE_BUFFER];
    char x[SIZE_BUFFER];  
    char A[SIZE_BUFFER];
    char z[SIZE_BUFFER];      
    char B[SIZE_BUFFER]; 
    char state[10];
    char **argvalue;
    size_t argnumber;
    char date[20];
};

// Structure pour contenir les valeurs extraites du fichier CSV
struct ServerConf {
    char uuid[40];
    char IP[50];
    char PORT[10];
};

struct ClientConf {
    char uuid[40];
    char p[SIZE_BUFFER];  // Nombre premier p
    char x[SIZE_BUFFER];  // Random x
    char date[20];
};

// Structure DHParameters 
struct DHParameters {
    unsigned int pre_canary;
    mpz_t p;    
    mpz_t x;   
    mpz_t B;      
    mpz_t KBx;  
    unsigned int post_canary;
}; 

//------------------------------------------------------------------------------// 
// Declaration des variables globales statiques
int ARGFCT = 0;
char DATEBUFFER[20];
char TIMEBUFFER[25];
char HTTP_RESPONSE[8192];// Variable globale pour stocker la reponse HTTP 
char JSON_RESPONSE[8192]; // Variable globale pour stocker la reponse json
struct SYD SYD_PARAMS;
struct ServerConf SVR_SYD_CONF_PARAMS;
struct ServerConf SVR_SP_CONF_PARAMS;
struct ClientConf CL_PARAMS;
char DIR_PATH[MAX_FILENAME_LEN]="."; // Chemin du repertoire du logiciel
char *LOG_FILE="SyD.log";

// Valeur de config du client
char *CONFIG_DIR="/conf/";
char CONFIG_PATH[MAX_FILENAME_LEN];
char *BDD_DIR="/bdd/";
char BDD_PATH[MAX_FILENAME_LEN]; 
char *CONFIG_FILE_SYD="ServerSYD.cfg";
char *CONFIG_FILE_SP="ServerProvider.cfg";
char *CONFIG_FILE_C="Client.cfg";
char SYD_BDD[MAX_FILENAME_PATH_LEN];  
char CONFIG_FILE_CL[41]="12345678-dead-face-beef-987654321000.CL"; // Valeurs canaries
char SERVER_SYD_UUID[40]="12345678-dead-face-beef-987654321000";
char SYD_UUID[40]="12345678-dead-beef-face-987654321000";
char CL_UUID[40]="11111111-dead-face-beef-987654321000";
const char *REGEX_UUID = "^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$";
char CLIENTKEY[1024];
char REQUESTKEY[1024];
char INIT[64];

// Valeur de l'url de l'API du SYD
const char *url = "/api/";

// Configuration des characteristiques de la Prod (le debug est interdit)
char *HOST = "127.0.0.1";
char *PORT = "443";

// Variable de stockage de la liste des UUID 
char LIST_UUID[9][40];
size_t NB_UUID = 0;

// Variables fichier entrée et sortie  (SYD et déchiffré) 
char SYDFILE[MAX_FILENAME_LEN]; // nom de l'archive
char FILENAME[MAX_FILENAME_LEN]; // nom du fichier a sécuriser
char PATH_OUT_FILE[MAX_FILENAME_LEN]; // Chemin de sortie du fichier contenu dans le SyD

// Variables de gestion du fichier SyD
size_t MAX_CL_COUNT = 100; // nombre de client max autorisé
char USERS[SIZE_BUFFER];
char DATA[MAX_FILES_SIZE_30P];
char UNCIPHER_DATA[MAX_FILES_SIZE];
char TAG[64];


//------------------------------------------------------------------------------//
//-----------------------------DEBUG-ON-----------------------------------------//
//------------------------------------------------------------------------------// 
// Activation du mode Debug Off=0 On=1 
int DEBUG = 0;

//------------------------------------------------------------------------------// 
// Debug Fonction pour afficher les valeurs de configuration 
void Display_json(const struct JsonValues *jvals) {
printf("------------------------------------------------------------------\n");
    for (size_t i = 0; i < jvals->entry_count; i++) {
        printf(" |Display_Json| %s: %s\n", jvals->entries[i].key, jvals->entries[i].value);
    }
}

//------------------------------------------------------------------------------// 
// Debug Fonction pour afficher les valeurs du fichier de reply.json dans le SYD
void Display_SYD(struct SYD *SYDVALS) {   
printf("------------------------------------------------------------------\n");
    printf(" |Display_SYD| UUID: %s\n", SYDVALS->uuid);
    printf(" |Display_SYD| date: %s\n", SYDVALS->date);
    printf(" |Display_SYD| g: %s\n", SYDVALS->g);
    printf(" |Display_SYD| p: %s\n", SYDVALS->p);
    printf(" |Display_SYD| x: %s\n", SYDVALS->x);    
    printf(" |Display_SYD| A: %s\n", SYDVALS->A);
    printf(" |Display_SYD| z: %s\n", SYDVALS->z);
    printf(" |Display_SYD| B: %s\n", SYDVALS->B);
    printf(" |Display_SYD| State: %s\n", SYDVALS->state);   
    if ( SYDVALS->argnumber > 0) {
      printf(" |Display_SYD| argnumber: %ld\n", SYDVALS->argnumber); 
      for (size_t i = 0; i < SYDVALS->argnumber; i++) { 
      printf(" |Display_SYD| argvalue[%ld]: %s\n", i, SYDVALS->argvalue[i]);
      } 
    }
}

//------------------------------------------------------------------------------//
//-----------------------------DEBUG-OFF----------------------------------------//
//------------------------------------------------------------------------------// 

//------------------------------------------------------------------------------// 
// Fonction pour obtenir la date et l'heure actuelles sous forme de chaîne de caractères
void Get_current_date(char *DATEBUFFER, size_t taille) {
    time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);
    strftime(DATEBUFFER, taille, "%Y-%m-%d", local_time);
}

// Fonction pour obtenir la date et l'heure actuelles sous forme de chaîne de caractères
void Get_current_time(char *TIMEBUFFER, size_t size) {
    time_t current_time = time(NULL);
    struct tm *local_time = localtime(&current_time);
    strftime(TIMEBUFFER, size, "%Y-%m-%d-%H:%M:%S", local_time);
}

// Fonction de collecte et d'ecriture des logs
void Write_log(const char *filename, const char *line) {
    // Ouvrir le fichier en mode ajout
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        // Creer un message d'erreur avec le nom du fichier
        char err_msg[256];
        memset(err_msg, '\0', sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "Write_log : File opening error %s", filename);
        perror(err_msg);
        memset(err_msg, '\0', sizeof(err_msg));
        return;
    }

    Get_current_time(TIMEBUFFER, sizeof(TIMEBUFFER));    
    // Ajouter la nouvelle ligne e la fin du fichier de log
    if (fprintf(file, "%s:%s\n", TIMEBUFFER, line) < 0) {
        // Creer un message d'erreur avec le nom du fichier
        char err_msg[256];
        memset(err_msg, '\0', sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "Write_log : Write file error %s", filename);
        perror(err_msg);
        fclose(file);
        memset(err_msg, '\0', sizeof(err_msg));
        return;
    }

    // Fermer le fichier de log
    if (fclose(file) != 0) {
        // Creer un message d'erreur avec le nom du fichier
        char err_msg[256];
        memset(err_msg, '\0', sizeof(err_msg));
        snprintf(err_msg, sizeof(err_msg), "Write_log : Closing file error %s", filename);
        perror(err_msg);
        memset(err_msg, '\0', sizeof(err_msg));
    }
}

//------------------------------------------------------------------------------// 
// Verification des arguments
// Fonction pour verifier si une chaine correspond a une expression reguliere
int Match_regex(const char *string, const char *pattern) {
    regex_t regex;
    int testregex; // variable de validation de la regex
        if (DEBUG == 1) {
              printf(" |Match Regex| Valeur %s Regex %s ", string, pattern);
        }
    // Compilation de l'expression reguliere
    testregex = regcomp(&regex, pattern, REG_EXTENDED);
    if (testregex) {
          char errorline[1024];
          memset(errorline, '\0', sizeof(errorline));
          sprintf(errorline, "Match_Regex:Regex compilation error pattern %s ", pattern);
          Write_log(LOG_FILE, errorline);
          memset(errorline, '\0', sizeof(errorline));     
        // fprintf(stderr, "Erreur de compilation de la regex\n");
        return 558;
    }

    // Comparer la chaine avec l'expression reguliere
    testregex = regexec(&regex, string, 0, NULL, 0);
    regfree(&regex);  // Liberer la memoire allouee pour l'expression reguliere

    if (!testregex) {
        if (DEBUG == 1) {
              printf(" |Match Regex| Regex trouvee : %d ", testregex);
        }
        return 1;  // Correspondance trouvee
    } else if (testregex == REG_NOMATCH) {
            if (DEBUG == 1) {
              printf(" |Match Regex| Regex non trouvee : %d ", testregex);
        }
        return 0;  // Aucune correspondance
    } else {
        char msgbuf[100];
        memset(msgbuf, '\0', sizeof(100));
        regerror(testregex, &regex, msgbuf, sizeof(msgbuf));
            if (DEBUG == 1) {
              printf(" |Match Regex| Erreur de correspondance de l'expression reguliere : %s ", msgbuf);
            }
        char regexerror[256];
        memset(regexerror, '\0', sizeof(regexerror)); 
        sprintf(regexerror, "Regex generic error:%s", msgbuf);
        Write_log(LOG_FILE, regexerror); 
        memset(msgbuf, '\0', sizeof(100));
        return 558;
    }
    // remise a 0 du debut de la chaine de caractère
}

//------------------------------------------------------------------------------// 
// Verification de la presence d'un fichier
char *Get_executable_dir() {
    static char exe_dir[MAX_FILENAME_LEN];
    char exe_path[MAX_FILENAME_LEN];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1); // utilise la lib unistd.h
    if (len == -1) {
        return NULL;
    }
    exe_path[len] = '\0'; // ajout de la fin de chaine
    // Extraire le répertoire
    char *last_slash = strrchr(exe_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        strncpy(exe_dir, exe_path, sizeof(exe_dir));
    }
    return exe_dir;
}

//------------------------------------------------------------------------------// 
// Verification de la presence d'un fichier
int Presence_Ref(const char *filename) {
    // Ouvrir le fichier en mode lecture pour verifier sa presence 
    
        FILE *file = fopen(filename, "r");
    if (file) {
        return 0; // le fichier existe
    } else { 
        return 10; // le fichier n'existe pas
    }
return 0;
}

//------------------------------------------------------------------------------//
// Fonction d'usage du programme
void Usage (char *NOM) {
printf ("Usage : %s\n", NOM);
printf ("Usage : %s -a <./mon_conteneur.syd> <UUID> <UUID>: demande la creation d'un conteneur et ajout de maximum 5 d'identifiants\n", NOM);
printf ("Usage : %s -u <./mon_conteneur.syd> <repertoire de sortie> : ouvre le conteneur dans le <repertoire>\n", NOM);
printf ("Usage : %s -c <./mon_conteneur.syd> <./fichier> : enregistre dans le conteneur le <fichier>\n", NOM);
printf ("Usage : %s -i : Initialise le client sur l'IGCS\n", NOM);
printf ("Usage : %s -s : Le client souscrit au SP\n", NOM);
printf ("Usage : %s -h : Affiche cette aide\n", NOM);
}

//------------------------------------------------------------------------------//
// Fonction d'analyse des parametres passes au programme
int Select_usage (struct ProgParams *PROGARGS) {


  char NOM[50];
  size_t j =0;
  snprintf(NOM, sizeof(NOM), "%s", PROGARGS->values[0]);
  NOM[sizeof(NOM) - 1] = '\0';
  if (DEBUG == 1) { printf("------------------------------------------------------------------\n");}
  if (DEBUG == 1) { printf(" |Select_usage| PROGARGS->entry_number : %ld\n", PROGARGS->entry_number);}


  if ( PROGARGS->entry_number < 2) {
    if (DEBUG == 1) { printf(" |Select_usage| PROGARGS->entry_number : %ld < 2\n", PROGARGS->entry_number);}
    ARGFCT = 0;
  } else {
  for (size_t i = 0; i < PROGARGS->entry_number; i++) {
        if (strcmp(PROGARGS->values[i], "-h") == 0) {
              ARGFCT = 0;
        } else if (strcmp(PROGARGS->values[i], "-a") == 0) {
               if (DEBUG == 1) { printf(" |Select_usage| Demande d'un conteneur au SP\n");}
              ARGFCT = 1;                
        } else if (strcmp(PROGARGS->values[i], "-u") == 0) {
               if (DEBUG == 1) { printf(" |Select_usage| Dechiffrement d'un SYD\n");}
              ARGFCT = 2;                
        } else if (strcmp(PROGARGS->values[i], "-c") == 0) {
               if (DEBUG == 1) { printf(" |Select_usage| Chiffrement d'un SYD\n");}
              ARGFCT = 3;                           
        } else if (strcmp(PROGARGS->values[i], "-i") == 0) {
               if (DEBUG == 1) { printf(" |Select_usage| Initialisation des donnees de configuration du SYD\n");}
              ARGFCT = 4;                       
        } else if (strcmp(PROGARGS->values[i], "-s") == 0) {
               if (DEBUG == 1) { printf(" |Select_usage| Souscription au SP\n");}
              ARGFCT = 5;                       
        } else {
          // Copie des valeurs dans les variables globales
          
        // Gestion des arguments pour la demande d'un conteneur  ( -a <./mon_conteneur.syd> <UUID> <UUID>)
          if (ARGFCT == 1 && i == 2) {
              snprintf(SYDFILE, sizeof(SYDFILE), "%s", PROGARGS->values[2]);
              if (DEBUG == 1) { printf(" |Select_usage| FCT = -a & SyDFile = %s\n", SYDFILE);}    

          } else if (ARGFCT == 1 && i > 2 && i < 6) {
              if (DEBUG == 1) { printf(" |Select_usage| FCT = -a & arg[%ld] = %s\n", i, PROGARGS->values[2]);}
              if (Match_regex(PROGARGS->values[3], REGEX_UUID) == 1) {
                snprintf(LIST_UUID[j], sizeof(LIST_UUID), "%s", PROGARGS->values[i]);
                if (DEBUG == 1) { printf(" |Select_usage| UUID[%ld] %s\n", j, LIST_UUID[j]);}
                j++;
              } 
              
              // Récuperation du nom du fichier avec le chemin
              snprintf(FILENAME, sizeof(FILENAME), "%s", PROGARGS->values[3]);
              
          } else if (ARGFCT == 1 && PROGARGS->entry_number > 8) { // pour fixer à 5 partages max
            ARGFCT = 0; // cas pas supporté donc erreur
            return ARGFCT;
          }
      // Gestion des arguments pour dechiffrer un SyD  ( -u <./mon_conteneur.syd> <repertoire de sortie> )
          
          if (ARGFCT == 2 && i == 2) {
              snprintf(SYDFILE, sizeof(SYDFILE), "%s", PROGARGS->values[2]);
                // vérification de la présence du SyD
                int ret_pres_ref =Presence_Ref(SYDFILE); 

                if ( ret_pres_ref != 0) {                 
                  printf("Erreur le fichier SyD %s n'existe pas\n", SYDFILE);
                }
                
                
          } else if (ARGFCT == 2 && i == 3) {
              snprintf(PATH_OUT_FILE, sizeof(PATH_OUT_FILE), "%s", PROGARGS->values[3]);
          } else if (ARGFCT == 2 && i > 3){
            ARGFCT = 0; // cas pas supporté donc erreur
            return ARGFCT;
          }
      // Gestion des arguments pour chiffrer un fichier dans un SyD  ( -c <./mon_conteneur.syd> <./fichier> )
          if (ARGFCT == 3 && i == 2 ) {
              snprintf(SYDFILE, sizeof(SYDFILE), "%s", PROGARGS->values[2]);
              if (DEBUG == 1) { printf(" |Select_usage| fichier SYD %s\n", SYDFILE);}
          } else if (ARGFCT == 3 && i == 3) {
              snprintf(FILENAME, sizeof(FILENAME), "%s", PROGARGS->values[3]);
              if (DEBUG == 1) { printf(" |Select_usage| fichier a chiffrer %s\n", FILENAME);}
          } else if (ARGFCT == 3 && i > 3) {
            ARGFCT = 0; // cas non supporté donc erreur
            return ARGFCT; 
          }
      // Gestion des arguments pour demander l'initialisation
          if (ARGFCT == 4 && PROGARGS->entry_number != 2) {
            ARGFCT = 0; // cas non supporté
            return ARGFCT; 
          }
      // Gestion des arguments pour demander la souscription
          if (ARGFCT == 5 && PROGARGS->entry_number != 2) {
            ARGFCT = 0; // cas non supporté 
            return ARGFCT; 
          }

        }
  }
  NB_UUID = j;
    } 

  if (DEBUG == 1) { 
    printf("------------------------------------------------------------------\n");
    printf(" |Select_usage| Nb Argument : %ld\n", PROGARGS->entry_number);
    printf(" |Select_usage| ArgFct : %d\n", ARGFCT);
    for (size_t i = 0; i < PROGARGS->entry_number; i++) {
      printf(" |Select_usage| ProgArgs_EntryNumber i : %ld\n", i);
      printf(" |Select_usage| ProgArgs_values |%s|\n", PROGARGS->values[i]);   
    }
  }
  return ARGFCT;
}

//------------------------------------------------------------------------------// 
// Fonction pour initialiser une structure ServerConf
void Initialize_ServerConf(struct ServerConf *params) {
    strncpy(params->uuid, "123e4567-e89b-12d3-a456-426614174000", sizeof(params->uuid));
    params->uuid[sizeof(params->uuid) - 1] = '\0';
    strncpy(params->IP, "127.0.0.1", sizeof(params->IP));
    params->IP[sizeof(params->IP) - 1] = '\0';
    strncpy(params->PORT, "443", sizeof(params->PORT));
    params->PORT[sizeof(params->PORT) - 1] = '\0';    
}

//------------------------------------------------------------------------------//
// Fonction pour libérer les paramètres ServerConf
void Free_ServerConf(struct ServerConf *params) {
    memset(params->uuid, '\0', sizeof(params->uuid));
    memset(params->IP, '\0', sizeof(params->IP));
    memset(params->PORT, '\0', sizeof(params->PORT));
}

//------------------------------------------------------------------------------// 
// Fonction pour initialiser une structure SYD
void Initialize_SYD(struct SYD *params) {
    // Definir des valeurs par defaut 
    strncpy(params->uuid, "123e4567-e89b-12d3-a456-426614174000", sizeof(params->uuid));
    params->uuid[sizeof(params->uuid) - 1] = '\0';
    strncpy(params->g, "479439790", sizeof(params->g));
    params->g[sizeof(params->g) - 1] = '\0';   
    strncpy(params->p, "8650173992387", sizeof(params->p));
    params->p[sizeof(params->p) - 1] = '\0';
    strncpy(params->x, "1422664330", sizeof(params->x));
    params->x[sizeof(params->x) - 1] = '\0';            
    strncpy(params->A, "3930444547546", sizeof(params->A));
    params->A[sizeof(params->A) - 1] = '\0';
    strncpy(params->z, "562303595", sizeof(params->z));
    params->z[sizeof(params->z) - 1] = '\0';            
    strncpy(params->B, "2622741280182", sizeof(params->B));
    params->B[sizeof(params->B) - 1] = '\0';        
    strncpy(params->date, "1976-12-29", sizeof(params->date) - 1);
    params->date[sizeof(params->date) - 1] = '\0';    
    strncpy(params->state, "INIT", sizeof(params->state) - 1);
    params->state[sizeof(params->state) - 1] = '\0';
    params->argnumber = 0 ;
}

//------------------------------------------------------------------------------//
// Fonction pour libérer les paramètres SYD
void Free_SYD(struct SYD *params) {
    memset(params->uuid, '\0', sizeof(params->uuid));
    memset(params->g, '\0', sizeof(params->g));
    memset(params->p, '\0', sizeof(params->p));
    memset(params->x, '\0', sizeof(params->x));
    memset(params->A, '\0', sizeof(params->A));
    memset(params->z, '\0', sizeof(params->z));
    memset(params->B, '\0', sizeof(params->B));
    memset(params->date, '\0', sizeof(params->date));
}

void Initialize_dh_parameters(struct DHParameters *PARAMS) {
    // Initialiser les canaries
    PARAMS->pre_canary = CANARY_VALUE;
    mpz_init(PARAMS->p);
    mpz_init(PARAMS->x);   
    mpz_init(PARAMS->B);
    mpz_init(PARAMS->KBx);
    PARAMS->post_canary = CANARY_VALUE;

    // Définir des valeurs par défaut
    mpz_set_str(PARAMS->p, "0", 10);
    mpz_set_str(PARAMS->x, "0", 10);
    mpz_set_str(PARAMS->B, "0", 10);
    mpz_set_str(PARAMS->KBx, "0", 10);
}

//------------------------------------------------------------------------------//
// Fonction pour libérer les paramètres DH
void Free_dh_parameters(struct DHParameters *PARAMS) {
    mpz_clear(PARAMS->p);
    mpz_clear(PARAMS->x);
    mpz_clear(PARAMS->B);
    mpz_clear(PARAMS->KBx);  
}

//------------------------------------------------------------------------------// 
// Fonction pour liberer les variables utilisees pour lire les jsons
void Free_json_values(struct JsonValues *jvals) {
    for (size_t i = 0; i < jvals->entry_count; i++) {
        free(jvals->entries[i].key);
        free(jvals->entries[i].value);
    }
    free(jvals->entries);
}

//------------------------------------------------------------------------------//
//-----------------------------DEBUG-END----------------------------------------//
//------------------------------------------------------------------------------//

//------------------------------------------------------------------------------// 
// Envoi du POST HTTP

void Send_post(const char *conn_srv, const char *conn_port, const char *url, const char *json_data) {
    SSL_CTX *ctx;
    BIO *bio;

    // Initialisation OpenSSL
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());
    bio = BIO_new_ssl_connect(ctx);
    char conn_params[256];  // Taille suffisante pour contenir l'adresse complète
    snprintf(conn_params, sizeof(conn_params), "%s:%s", conn_srv, conn_port);

    BIO_set_conn_hostname(bio, conn_params);
    BIO_do_connect(bio);
    BIO_do_handshake(bio);

    // Construction de la requête HTTP
    char request[MAX_HTTP_RQST_SIZE];// attention limite la taille de la requete envoyée au serveur ne doit pas depasser MAX_HTTP_RQST_SIZE 1024 caratères
    snprintf(request, sizeof(request),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "\r\n%s",
             url, conn_srv, strlen(json_data), json_data);

    BIO_write(bio, request, strlen(request));

    // Lecture de la reponse HTTP
    int len = BIO_read(bio, HTTP_RESPONSE, sizeof(HTTP_RESPONSE) - 1);
    if (len > 0) {
        HTTP_RESPONSE[len] = '\0';  // Terminer la chaîne
    }
    // Nettoyage
    BIO_free_all(bio);
    SSL_CTX_free(ctx);  
    if (DEBUG == 1){printf(" |Send_post| HTTP_RESPONSE : %s \n", HTTP_RESPONSE);}
}

//------------------------------------------------------------------------------//
// Fonction de Hashage sha 256

int sha256(const char *str, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Erreur : échec de lallocation du contexte EVP_MD_CTX.\n");
        return 1;
    }

    // Initialisation du contexte SHA256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Erreur : échec de linitialisation EVP SHA256.\n");
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    // Ajout des données à hacher
    if (EVP_DigestUpdate(ctx, str, strlen(str)) != 1) {
        fprintf(stderr, "Erreur : échec de lajout des données à EVP SHA256.\n");
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    unsigned int hash_len = 0;

    // Finalisation du hachage
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1 || hash_len != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "Erreur : échec de la finalisation EVP SHA256.\n");
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    EVP_MD_CTX_free(ctx);
    return 0; // Succès
}

//------------------------------------------------------------------------------//
// Fonction d'encodage en Base64 via OpenSSL BIO
char *base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Pas de saut de ligne
    BIO_push(b64, bio);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    
    char *base64 = malloc(bufferPtr->length + 1);
    memcpy(base64, bufferPtr->data, bufferPtr->length);
    base64[bufferPtr->length] = '\0';

    BIO_free_all(b64);
    return base64;
}

//------------------------------------------------------------------------------//
// Fonction de décodage Base64
unsigned char *base64_decode(const char *input, int *length) {
    BIO *bio, *b64;
    int decodeLen = strlen(input);
    unsigned char *buffer = malloc(decodeLen);
    
    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    *length = BIO_read(b64, buffer, decodeLen);
    
    BIO_free_all(b64);
    return buffer;
}

//------------------------------------------------------------------------------//
// Fonction de chiffrement AES-GCM avec sortie en Base64
char *encrypt_AES_GCM_base64(const unsigned char *plaintext, int plaintext_len,
                             const unsigned char *key, const unsigned char *iv, char *hash_tag) {
    EVP_CIPHER_CTX *ctx;
    unsigned char ciphertext[plaintext_len + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16]; 
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    // Encodage Base64 des données chiffrées et du tag
    char *ciphertext_base64 = base64_encode(ciphertext, ciphertext_len);
    char *tag_base64 = base64_encode(tag, 16);
    sprintf(hash_tag, "%s", tag_base64);

    free(tag_base64);
    return ciphertext_base64; // Retourne le texte chiffré encodé en Base64
}

//------------------------------------------------------------------------------//
// Fonction de chiffrement AES-GCM d'un fichier en entrée avec sortie en Base64
char *encrypt_file_AES_GCM_base64(const char *filepath, const unsigned char *key,
                                  const unsigned char *iv,  char *hash_tag) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "? Impossible d'ouvrir le fichier : %s\n", filepath);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (filesize <= 0 || filesize > MAX_FILES_SIZE) { // if (filesize <= 0 || filesize > 50 * 1024 * 1024) { Limite de 50 Mo
        fclose(file);
        fprintf(stderr, "Taille de fichier invalide ou trop grande.\n");
        return NULL;
    }

    unsigned char *plaintext = malloc(filesize);
    if (!plaintext) {
        fclose(file);
        fprintf(stderr, "Erreur d'allocation mémoire.\n");
        return NULL;
    }

    fread(plaintext, 1, filesize, file);
    fclose(file);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *ciphertext = malloc(filesize + EVP_MAX_BLOCK_LENGTH);
    unsigned char tag[16];
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, filesize);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);

    char *ciphertext_base64 = base64_encode(ciphertext, ciphertext_len);
    char *tag_base64 = base64_encode(tag, 16);
    free(ciphertext);

    sprintf(hash_tag, "%s", tag_base64);
    free(tag_base64);

    return ciphertext_base64;
}

//------------------------------------------------------------------------------//
// Fonction de déchiffrement 
int decrypt_AES_GCM_base64(const char *ciphertext_base64, const char *tag_base64,
                           const unsigned char *key, const unsigned char *iv,
                           unsigned char *plaintext) {
    int ciphertext_len, tag_len;
    unsigned char *ciphertext = base64_decode(ciphertext_base64, &ciphertext_len);
    unsigned char *tag = base64_decode(tag_base64, &tag_len);

    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(tag);

    return ret > 0 ? plaintext_len + len : -1;
}

//------------------------------------------------------------------------------// 
// Extraction du JSON de la reponse HTTP

void Copy_json_rply_to_char() {
    char *json_start = strchr(HTTP_RESPONSE, '{');
    if (json_start) {
        strncpy(JSON_RESPONSE, json_start, sizeof(JSON_RESPONSE) - 1); // Copie le JSON dans la variable
        JSON_RESPONSE[sizeof(JSON_RESPONSE) - 1] = '\0'; // Assure la terminaison de la chaîne
    } else {
        printf("Erreur : Aucun JSON trouve dans la reponse.\n");
    }
}

//------------------------------------------------------------------------------// 
// Verification de la presence de la base des UUID et creation si besoin
int Presence_BDD(const char *filename) {
    // Ouvrir le fichier en mode lecture pour verifier sa presence 
    
        FILE *file = fopen(filename, "r");
    if (file) {
        return 0; // le fichier existe
    } else { 
        // Creation du fichier
        file = fopen(filename, "w");
        if (!file) { // erreur de creation du fichier
            Write_log(LOG_FILE, "Write_SYDFILE:577:Error create BDD file");
            exit(577);
        }
        // Ajouter la chaîne "SYD;UUID;DATE;P;G;A;" en première ligne
        fprintf(file, "SYD;UUID;DATE;P;X;\n");
        fclose(file);
    }
return 0;
}

//------------------------------------------------------------------------------// 
// Fonction d'ecriture dans la base des UUID
int Write_SYD(const char *filename, struct SYD *params) {
    // Ouvrir le fichier en mode ajout

    char separateur[] = ";";

    char line[33000];
    memset(line, '\0', sizeof(line)); 

        strcat(line, "CL;");
        strcat(line, params->uuid);
        strcat(line, separateur);
        strcat(line, params->date);
        strcat(line, separateur);
        strcat(line, params->p);
        strcat(line, separateur);
        strcat(line, params->x);
        strcat(line, separateur);
        strcat(line, params->A);
        strcat(line, separateur);
       
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        return 577;
    }

    // Ajouter la nouvelle ligne à la fin du fichier
    if (fprintf(file, "%s\n", line) < 0) {
        return 578;
    }

    // Fermer le fichier des UUID
    if (fclose(file) != 0) {
        return 579;
    }   
    memset(line, '\0', sizeof(line));
    return 0;
}

//------------------------------------------------------------------------------//
// Fonction pour créer le fichier SYD
int Write_CloseSYD(char *sydfilename, char *encryptfilename, char *data) {

       //printf(" |Write_CloseSYD| sydfilename %s encryptfilename %s \n", sydfilename, encryptfilename );

    // Créer le fichier de sortie 
    FILE *file = fopen(sydfilename, "w");
    if (file == NULL) {
        printf(" |Write_CloseSYD| Erreur lors de la création du fichier\n");
        return 10;
    }

    fprintf(file, "{\n");
    fprintf(file, "    \"SYD\": \"%s\",\n",SYD_UUID);
    fprintf(file, "    \"USER\": \"%s\",\n", USERS);
    fprintf(file, "    \"FILENAME\": \"%s\",\n", encryptfilename);
    fprintf(file, "    \"DATA\": \"%s\",\n", data);   
    fprintf(file, "    \"TAG\": \"%s\",\n", TAG);
    fprintf(file, "}");

    // Fermer le fichier
    fclose(file);
    // Retour succes
    return 0;
}


//------------------------------------------------------------------------------//
// Fonction pour créer une réponse en cas d'erreur dans le traitement 
int Write_Ref(struct SYD *params) {
    char filename[MAX_FILENAME_PATH_LEN]; 
    memset(filename, '\0', sizeof(filename));
    char type[5];
    memset(type, '\0', sizeof(type)); 
    sprintf(type, "CL");
    
    // Utiliser les variables pour construire le nom de fichier
    snprintf(filename, sizeof(filename), "%s%s.%s", CONFIG_PATH, SERVER_SYD_UUID, type);
    // Créer le fichier
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        Write_log(LOG_FILE, "Write_Ref:571:Error opening Ref file");
        exit(571);
    }
    // Contenu Reponse 
    if (fprintf(file, "{\"UUID\": \"%s\"}\n", params->uuid) < 0) {
        Write_log(LOG_FILE, "Write_Ref:572:Error Writing in Ref file");
        return 572;
      }
    // Fermer le fichier
    if (fclose(file) != 0) {
      Write_log(LOG_FILE, "Write_Ref:573:Error closing Ref file");
      return 573;
    }
    return 0;
}


//------------------------------------------------------------------------------//
// Fonction pour créer une réponse en cas d'erreur dans le traitement 
void Write_SYDFILE() {
    if (DEBUG == 1) { 
            printf("------------------------------------------------------------------\n");
            printf(" |Write_SYDFILE| SYD File : %s\n", SYDFILE);
        }
    
    // Créer un fichier avec le nom passé en para
    FILE *file = fopen(SYDFILE, "w");
    if (file == NULL) {
        Write_log(LOG_FILE, "Write_SYDFILE:580:Error opening SyD file");
        exit(580);
    }
    // Contenu Reponse 
    fprintf(file, "%s", JSON_RESPONSE);
    // Fermer le fichier
    fclose(file);
}

//------------------------------------------------------------------------------// 
// Fonctions de lecture des JSONs
// Fonction pour lire les valeurs de configuration depuis un fichier JSON
int Read_json(const char *filename, struct JsonValues *jvals) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        Write_log(LOG_FILE, "READ-JSON:501:Error opening file");
        return 501;
    }
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *data = malloc(length + 1);
    if (!data) {
    Write_log(LOG_FILE, "READ-JSON:500:Allocation memory error");
    fclose(file);
    return 500;
    }
    fread(data, 1, length, file);
    fclose(file);
    data[length] = '\0';

    // Compter les paires clé-valeur
    jvals->entry_count = 0;
    for (char *ptr = data; *ptr != '\0'; ptr++) {
        if (*ptr == ':') {
            jvals->entry_count++;
        }
    }
    // printf("Debug Read_json : entry_count %ld\n", jvals->entry_count); 
    jvals->entries = malloc(jvals->entry_count * sizeof(struct JsonEntry));
    if (!jvals->entries) {
        Write_log(LOG_FILE, "READ-JSON:500:Allocation memory error");
        
        free(data);
        return 500;
    }
    
    // Parser les paires clé-valeur
    size_t i = 0;
    char *key_start, *key_end, *value_start, *value_end, *colon;
    for (char *ptr = data; *ptr != '\0'; ptr++) {
        
        if (*ptr == '"') {
            key_start = ptr + 1;
            key_end = strchr(key_start, '"');
            if (key_end == NULL) {
                Write_log(LOG_FILE, "READ-JSON:400:Parsing error malformed key");               
                break;
                
            }
            *key_end = '\0';

            colon = strchr(key_end + 1, ':');
            if (colon == NULL || colon > strchr(key_end + 1, '\n')) {
                Write_log(LOG_FILE, "READ-JSON:400:Parsing error key without :");
                break;
            }

            // Ignorer les espaces entre les deux points et la valeur
            value_start = colon + 1;
            while (*value_start == ' ' || *value_start == '\t') {
                value_start++;
            }

            if (*value_start != '"') {
                Write_log(LOG_FILE, "READ-JSON:400:Parsing error malformed key");
                break;
            }
            value_start++;
            value_end = strchr(value_start, '"');
            if (value_end == NULL) {
                Write_log(LOG_FILE, "READ-JSON:400:Parsing error malformed key");
                break;
            }
            *value_end = '\0';

            jvals->entries[i].key = strdup(key_start);
            //printf(" |Read_Json| Key : %s\n", jvals->entries[i].key); // Dev Debug 
            jvals->entries[i].value = strdup(value_start);
            //printf(" |Read_Json| Value : %s\n", jvals->entries[i].value); // Dev Debug
            if (!jvals->entries[i].key || !jvals->entries[i].value) {
                Write_log(LOG_FILE, "READ-JSON:500:jvals Allocation memory error");
                return 500;
            }
            i++;
            ptr = value_end;

        }
    }

    // Vérifier si le parsing est complet
    if (i < jvals->entry_count) {
        Write_log(LOG_FILE, "READ-JSON:400:Parsing error missing or malformed key");
        for (size_t j = 0; j < i; j++) {
            free(jvals->entries[j].key);
            free(jvals->entries[j].value);
        }
        free(jvals->entries);
        free(data);
        return 400;
    }
    free(data);
    return 0;
}

//------------------------------------------------------------------------------// 
// Fonctions de lecture des JSONs
// Fonction pour lire les valeurs depuis une chaine de caractere JSON
int Read_char_json(const char *data, struct JsonValues *jvals) {
    if (data == NULL) {
        //fprintf(stderr, "Read_json Erreur : donnees JSON nulles\n");
        Write_log(LOG_FILE, "Read_char_json:204:NO_CONTENT");
        return 204;
    }
        if (DEBUG == 1) { 
            printf(" |Read_char_json| 04-1.1 Read Json data recieved");
        }
    jvals->entry_count = 0;
    jvals->entries = NULL;
    const char *ptr = data;
    while (*ptr != '\0') {
        if (*ptr == '"') {
            // Extraire la clé
            const char *key_start = ptr + 1;

            const char *key_end = strchr(key_start, '"');
            if (key_end == NULL) {
                Write_log(LOG_FILE, "Read_char_json:400:Parsing error malformed key");
                return 400;
            }
            const char *colon = strchr(key_end, ':');
            if (colon == NULL) {
                Write_log(LOG_FILE, "Read_char_json:400:Parsing error key without :");
                return 400;
            }
            // Extraire la valeur
            const char *value_start = colon + 1;
            while (*value_start == ' ' || *value_start == '\t') {
                value_start++;
            }
            if (*value_start != '"') {
                Write_log(LOG_FILE, "Read_char_json:400:Parsing error malformed key");
                return 400;
            }
            const char *value_end = strchr(value_start + 1, '"');
            if (value_end == NULL) {
                Write_log(LOG_FILE, "Read_char_json:400:Parsing error malformed key");
                return 400;
            }
            // Allouer et stocker la paire clé-valeur
            jvals->entries = realloc(jvals->entries, (jvals->entry_count + 1) * sizeof(struct JsonEntry));
            if (!jvals->entries) {
                Write_log(LOG_FILE, "Read_char_json:500:jvals Allocation memory error");
                return 500;
            }
            jvals->entries[jvals->entry_count].key = strndup(key_start, key_end - key_start);
            jvals->entries[jvals->entry_count].value = strndup(value_start + 1, value_end - value_start - 1);
            jvals->entry_count++;
            ptr = value_end;
        }
        ptr++;
    }
    return 0;
}

//------------------------------------------------------------------------------// 
// Analyse du retour http pour vérifier s'il n'y a pas d'erreur
int Detect_error(const char* text) {

    struct JsonValues jvals;
    if (DEBUG == 1) { printf(" |Detect_error| lecture valeur %s\n", text );}
    // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_char_json = Read_char_json(text, &jvals );
    if ( ret_Read_char_json != 0 ) {
        Write_log(LOG_FILE, "Detect_error:10:JSON_RESPONSE read error");
        return 10;
    }
    // Fonctions de debug de gestion des JSONs 
      // Afficher les valeurs lues
    if (DEBUG == 1) { Display_json(&jvals); }
    for (size_t i = 0; i < jvals.entry_count; i++) {
        if (strcmp(jvals.entries[i].key, "Error") == 0) {
        
            int ret_err_val = (int)strtol(jvals.entries[0].value, NULL, 10);
            
            if (DEBUG == 1) {
            printf("------------------------------------------------------------------\n");
            printf(" |Detect_error| Return code : %d\n", ret_err_val);
            }
        return ret_err_val; // interpreter le retour 201(souscrit) 200(déjà souscrit) ou autre qui sont des erreurs dans le client
        }
    }
    return 0;
}

//------------------------------------------------------------------------------// 
// Fonction pour Transferer les Valeurs JSON vers les Parametres SYD
void Transfer_Server_Conf(const struct JsonValues *jvals, struct ServerConf *srv_params) {

    for (size_t i = 0; i < jvals->entry_count; i++) {
            if (DEBUG == 1) {printf(" |Transfer_Server_Conf| i : %ld/%ld|\n", i, jvals->entry_count);
                printf(" |Transfer_Server_Conf| Key : %s|\n", jvals->entries[i].key);
            }   
        if (strcmp(jvals->entries[i].key, "uuid") == 0) {
            size_t longueuruuid = strlen(jvals->entries[i].value) + 1;               // Taille de la chaine de caractere              
            snprintf(srv_params->uuid, longueuruuid, "%s", jvals->entries[i].value);
              if (DEBUG == 1) {printf(" |Transfer_Server_Conf| SRV_PARAMS uuid: %s|\n", srv_params->uuid);}
         }  else if (strcmp(jvals->entries[i].key, "IP") == 0) {
            size_t longueurg = strlen(jvals->entries[i].value) + 1; 
            snprintf(srv_params->IP, longueurg, "%s", jvals->entries[i].value);       
              if (DEBUG == 1) {printf(" |Transfer_Server_Conf| SRV_PARAMS g: %s|\n", srv_params->IP);}
        }  else if (strcmp(jvals->entries[i].key, "PORT") == 0) {
            size_t longueurp = strlen(jvals->entries[i].value) + 1;
            snprintf(srv_params->PORT, longueurp, "%s", jvals->entries[i].value); 
              if (DEBUG == 1) {printf(" |Transfer_Server_Conf| SRV_PARAMS p: %s|\n", srv_params->PORT);}   
        }
    }
}


//------------------------------------------------------------------------------//
// Lecture du fichier de configuration du client
int Read_config_server(const char *filename, struct ServerConf *srv_params) {
     
      if (DEBUG == 1) { 
      printf("------------------------------------------------------------------\n");
      }
  // Declaration des variables
    struct JsonValues jvals;
  //struct DHParameters DH_PARAMS;
      if (DEBUG == 1) { printf(" |Read_config_server| lecture fichier %s\n", filename );}
  // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_json = Read_json(filename, &jvals);
    if ( ret_Read_json != 0 ) {
        Write_log(LOG_FILE, "Read_config_server:10:Configuration file read error");
        return 10;
    }
  // Fonctions de debug de gestion des JSONs 
      // Afficher les valeurs lues
      if (DEBUG == 1) { Display_json(&jvals); }
    Transfer_Server_Conf(&jvals, srv_params); 
    
    Free_json_values(&jvals);
    return 0;
}

//------------------------------------------------------------------------------//
// Lecture du fichier de configuration du client
int Read_config_client(const char *filename) {
     
      if (DEBUG == 1) { 
      printf("------------------------------------------------------------------\n");
      }
  // Declaration des variables
    struct JsonValues jvals;
  //struct DHParameters DH_PARAMS;
      if (DEBUG == 1) { printf(" |Read_config| lecture fichier %s\n", filename );}
  // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_json = Read_json(filename, &jvals);
    if ( ret_Read_json != 0 ) {
        Write_log(LOG_FILE, "Read_config_client:10:Configuration file read error");
        return 10;
    }
  // Fonctions de debug de gestion des JSONs 
      // Afficher les valeurs lues
      if (DEBUG == 1) { Display_json(&jvals); }

        for (size_t i = 0; i < jvals.entry_count; i++) {
            if (DEBUG == 1) {printf(" |Read_config_client| i : %ld/%ld|\n", i, jvals.entry_count);
                printf(" |Read_config_client| Key : %s|\n", jvals.entries[i].key);
            }   
        if (strcmp(jvals.entries[i].key, "SAFE") == 0) {
            size_t longueurSAFE = strlen(jvals.entries[i].value) + 1;   
            if ( longueurSAFE < 1024) {                      
            snprintf(CLIENTKEY, longueurSAFE, "%s", jvals.entries[i].value);
            } else {
            snprintf(CLIENTKEY, 1023, "%s", jvals.entries[i].value);
            CLIENTKEY[1024] = '\0';
            }
            
              if (DEBUG == 1) {printf(" |Read_config_client| SAFE: %s|\n", CLIENTKEY);}
        }
        }
    
    Free_json_values(&jvals);
    return 0;
}


//------------------------------------------------------------------------------//
// Lecture du fichier de configuration du client
int Read_uuid_client(const char *filename) {
     
      if (DEBUG == 1) { 
            printf("------------------------------------------------------------------\n");
      }
  // Declaration des variables
    struct JsonValues jvals;
  //struct DHParameters DH_PARAMS;
      if (DEBUG == 1) { printf(" |Read_uuid_client| lecture fichier %s\n", filename );}
  // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_json = Read_json(filename, &jvals);
    if ( ret_Read_json != 0 ) {
        Write_log(LOG_FILE, "Read_uuid_client:10:Configuration file read error");
        return 10;
    }
  // Fonctions de debug de gestion des JSONs 
      // Afficher les valeurs lues
    if (DEBUG == 1) { Display_json(&jvals); }
    for (size_t i = 0; i < jvals.entry_count; i++) {
        if (DEBUG == 1) {
            printf(" |Read_config_client| i : %ld/%ld|\n", i, jvals.entry_count);
            printf(" |Read_config_client| Key : %s|\n", jvals.entries[i].key);
        }   
        if (strcmp(jvals.entries[i].key, "UUID") == 0) {
            size_t longueurUUID = strlen(jvals.entries[i].value) + 1;                     
            snprintf(CL_UUID, longueurUUID, "%s", jvals.entries[i].value);
        }       
        if (DEBUG == 1) {printf(" |Read_uuid_client| UUID: %s|\n", CLIENTKEY);}
    } 

    Free_json_values(&jvals);
    return 0;
}

//------------------------------------------------------------------------------//
// Lecture du fichier de configuration du client
int Read_reply() {
     
      if (DEBUG == 1) { 
      printf("------------------------------------------------------------------\n");
      }
  // Declaration des variables
    struct JsonValues jvals;
  //struct DHParameters DH_PARAMS;
      if (DEBUG == 1) { printf(" |Read_reply| lecture valeur %s\n", JSON_RESPONSE );}
  // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_char_json = Read_char_json(JSON_RESPONSE, &jvals );
    if ( ret_Read_char_json != 0 ) {
        Write_log(LOG_FILE, "Read_reply:10:JSON_response read error");
        return 10;
    }
  // Fonctions de debug de gestion des JSONs 
      // Afficher les valeurs lues
      if (DEBUG == 1) { Display_json(&jvals); }
    // Dechiffrer la valeur de X
        char tag[64];
        char ciphertext_base64[4096];
        unsigned char decryptedtext[4096];
        unsigned char hash_Key[SHA256_DIGEST_LENGTH];
        unsigned char iv[12];  // IV basé sur le 12 permiers caractères de P
        memset(iv, '\0', sizeof(iv));
        
        if ( sha256(REQUESTKEY, hash_Key) != 0) {
            printf("14\n");
        }
        
        // lecture des valeurs jvals de X P et TAG
        for (size_t i = 0; i < jvals.entry_count; i++) {
            if (DEBUG == 1) {printf(" |Transfert_SYD_values| i : %ld/%ld|\n", i, jvals.entry_count);
                printf(" |Transfert_SYD_values| Key : %s|\n", jvals.entries[i].key);
            }   
         if (strcmp(jvals.entries[i].key, "UUID") == 0) {
              size_t longueuruuid = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(SYD_PARAMS.uuid, longueuruuid, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Transfert_SYD_values| UUID: %s|\n", SYD_PARAMS.uuid);}   
        } else if (strcmp(jvals.entries[i].key, "DATE") == 0) {
              size_t longueurdate = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(SYD_PARAMS.date, longueurdate, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Transfert_SYD_values| DATE: %s|\n", SYD_PARAMS.date);}   
        } else if (strcmp(jvals.entries[i].key, "P") == 0) {
              size_t longueurp = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(SYD_PARAMS.p, longueurp, "%s", jvals.entries[i].value);
              strncpy((char *)iv, jvals.entries[i].value, 12); 
              if (DEBUG == 1) {printf(" |Transfert_SYD_values| P: %s|\n", SYD_PARAMS.p);}   
        } else if (strcmp(jvals.entries[i].key, "X") == 0) {
            size_t longueurx = strlen(jvals.entries[i].value) + 1; 
            snprintf(ciphertext_base64, longueurx, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Transfert_SYD_values| X : %s|\n", ciphertext_base64);}
        } else if (strcmp(jvals.entries[i].key, "TAG") == 0) {
            size_t longueurtag = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
            snprintf(tag, longueurtag, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Transfert_SYD_values| TAG : %s|\n", tag);}
        } else if (strcmp(jvals.entries[i].key, "SYD") == 0) {
            size_t longueurSYD = strlen(jvals.entries[i].value) + 1;
            snprintf(SERVER_SYD_UUID, longueurSYD, "%s", jvals.entries[i].value);  
              if (DEBUG == 1) {printf(" |Transfert_SYD_values| SERVER_SYD_UUID: %s|\n", SERVER_SYD_UUID);}  
        }  
    }
    
    // Dechiffement de X 
        int decrypted_len = decrypt_AES_GCM_base64(ciphertext_base64, tag, hash_Key, iv, decryptedtext);
    if (decrypted_len >= 0) {
        decryptedtext[decrypted_len] = '\0';
    } else {
        printf("Echec du dechiffrement !\n");
    }
    // Chiffrement de x pour stockage dans la BDD.syd locale
    if ( sha256(CLIENTKEY, hash_Key) != 0) {
      printf("14\n");
        }
    char *encrypted_base64 = encrypt_AES_GCM_base64(decryptedtext, strlen((char *)decryptedtext), hash_Key, iv, tag);
    // Transfert dans la structure SYD pour traitement ultérieurs des constantes recues   

    // Ajout de la valeur de x dechiffrée 
    sprintf(SYD_PARAMS.x, "%s", encrypted_base64);
    sprintf(SYD_PARAMS.A, "%s", tag);
    if (DEBUG == 1) { Display_SYD(&SYD_PARAMS); }
    
    Free_json_values(&jvals);
    return 0;
}

//------------------------------------------------------------------------------// 
// Génération d'une chaine de caractères aléatoires

void Generation_chaine(char *result, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    size_t charset_size = strlen(charset);

    for (size_t i = 0; i < length; i++) {
        result[i] = charset[rand() % charset_size];
    }
    result[length] = '\0'; // Null-terminate la chaîne
}

void Derivation_chaine(char *dest, const char *src1, const char *src2) {
    size_t len1 = strlen(src1);
    size_t len2 = strlen(src2);
    size_t maxLen = len1 > len2 ? len1 : len2;

    for (size_t i = 0; i < maxLen; i++) {
        char c1 = i < len1 ? src1[i] : 0;
        char c2 = i < len2 ? src2[i] : 0;
        dest[i] = c1 | c2;
    }
    dest[maxLen] = '\0';
}

//------------------------------------------------------------------------------// 
// Creation du JSON permettant de faire la requete
void Create_Req_JSON(char *json_data) {

// Demande d'enrolement pour un CL 
char line[1024] = "{\"VERB\": \"CREA\", \"ARGS\": \"";

        strcat(line, "CL\", \"INIT\": \"");
        strcat(line, REQUESTKEY);
        strcat(line, "\"}");
      
  sprintf(json_data, "%s", line);       
}

//------------------------------------------------------------------------------// 
// Creation du JSON permettant de faire la souscription
void Create_Subs_JSON(struct SYD *params, char *json_data) {
char line[1024] = "{\"VERB\": \"SUBS\", \"CL\": \"";
        strcat(line, CL_UUID);
        strcat(line, "\", \"DATE\": \"");
        strcat(line, params->date);
        strcat(line, "\", \"P\": \"");
        strcat(line, params->p);
        strcat(line, "\", \"SYD\": \"");
        strcat(line, SYD_UUID);
        strcat(line, "\"}");
      
  sprintf(json_data, "%s", line);       
}

//------------------------------------------------------------------------------// 
// Creation du JSON permettant de faire la demande de service TANK
void Create_TANK_JSON(char *json_data) {
char line[1024] = "{ \"VERB\": \"TANK\", \"SYD\": \"";
        strcat(line, SYD_UUID);
        strcat(line, "\", ");
        if (NB_UUID > 0) {
          for (size_t i = 0; i < NB_UUID ; i++) {
           strcat(line, "\"CL\": \"");
           strcat(line, LIST_UUID[i]);
           strcat(line, "\", ");
          }
        } 
        strcat(line, "\"CL\": \"");
        strcat(line, CL_UUID);
        strcat(line, "\" }");
      
  sprintf(json_data, "%s", line);       
}

//------------------------------------------------------------------------------// 
// Lecture des variables associées à l'UUID dans la base
//int Read_BDD(const char *filename, const char *uuid, char *date, char *p, char *g, char *A) {
int Read_BDD(const char *filename, char *state, const char *uuid, char *date, char *p, char *x, char *tag) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        Write_log(LOG_FILE, "Read_BDD:577:Error opening BDD file");
        return 577;
    }

    char line[SIZE_BUFFER];
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ";");
        char *values[6];
        int i = 0;

        // Initialisation du tableau
        for (int j = 0; j < 6; j++) {
            values[j] = NULL;
        }

        // Remplissage du tableau de valeurs
        while (token && i < 6) {
            values[i++] = token;
            token = strtok(NULL, ";");
        }

        if (i < 6) {
            continue; // Ignore les lignes sans valeurs
        }

        // Comparaison de l'uuid et transfert des valeurs
        if (strcmp(values[1], uuid) == 0) {
            strncpy(state, values[0], 10);
            strncpy(date, values[2], 20);
            strncpy(p, values[3], SIZE_BUFFER);
            //snprintf(p, sizeof(SIZE_BUFFER), "%s", values[3]);
            strncpy(x, values[4], SIZE_BUFFER);
            //snprintf(g, sizeof(SIZE_BUFFER), "%s", values[4]);
            strncpy(tag, values[5], SIZE_BUFFER);
            //snprintf(A, sizeof(SIZE_BUFFER), "%s", values[5]);
            break;
        }
    }

    fclose(file);
    return 0;
}

//------------------------------------------------------------------------------// 
// Vérification de la présence de l'UUID dans la base
int Check_uuid_in_bdd(const char *filename, const char *uuid_to_check) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Erreur d'ouverture du fichier");
        return -1; // Retourne -1 en cas d'erreur d'ouverture de fichier
    }
    char buffer[SIZE_BUFFER];
    while (fgets(buffer, SIZE_BUFFER, file)) {
        // Extraire l'UUID de chaque ligne du fichier CSV
        char *token = strtok(buffer, ";");
        token = strtok(NULL, ";"); // permet de passer a la deuxieme colonne
        
        if (token != NULL) {
            // Comparer l'UUID extrait avec l'UUID à vérifier
            if (strcmp(token, uuid_to_check) == 0) {
                fclose(file);
                return 1; // Retourne 1 si l'UUID existe
            }
        }
    }
    fclose(file);
    return 0; // Retourne 0 si l'UUID n'existe pas
}

//------------------------------------------------------------------------------// 
// Lecture des variables associées à l'UUID dans la base structuré STATE:UUID;DATE;P;X
void Parsing_SYD_user(char *data) {

    size_t MAX_FIELDS = 5;
    char temp[SIZE_BUFFER];
    char fields[MAX_CL_COUNT][MAX_FIELDS][SIZE];
    size_t ptr = 0; 
    size_t line_count = 0;
    size_t cl_count = 0;

    while (data[ptr] != '\0' && line_count < MAX_CL_COUNT) {
        // Copie de la ligne dans temp
        int len = 0;
        while (data[ptr + len] != '\n' && data[ptr + len] != '\0') {
            if (len >= SIZE - 1) break;
            temp[len] = data[ptr + len];
            len++;
        }
        temp[len] = '\0';
        ptr += len;
        if (data[ptr] == '\n') ptr++;
        if (strlen(temp) == 0) continue;

        // Découpe des champs dans temp
        char *start = temp;
        char *sep = NULL;
        size_t field_count = 0;

        while ((sep = strchr(start, ';')) != NULL && field_count < MAX_FIELDS) {
            *sep = '\0';
            if (strlen(start) > 0) {
                strncpy(fields[line_count][field_count], start, SIZE - 1);
                fields[line_count][field_count][SIZE - 1] = '\0';  // ajout caractere de fin de chaine
                field_count++;
            }
            start = sep + 1;
        }

        // Dernier champ
        if (*start != '\0' && field_count < MAX_FIELDS) {
            strncpy(fields[line_count][field_count], start, SIZE - 1);
            fields[line_count][field_count][SIZE - 1] = '\0';
            field_count++;
        }
        line_count++;
    }

    // boucle qui dans chaque ligne va venir verifier que le premier champ est bien un CL
    for (size_t i = 0; i < line_count; i++) {
        if (strcmp(fields[i][0], "CL") == 0) {
            cl_count++;
        }
    }


    // boucle qui dans chaque ligne va venir comparer si l'UUID CL avec celui de la requete CL et ajoute les constantes dans READ
    for (size_t i = 0; i < line_count; i++) {
        if (DEBUG == 1) { 
            printf("------------------------------------------------------------------\n");
            printf(" |Parsing_SYD_user| Ligne %ld :\n", i + 1); 
        }
                int check = 0;
                check = Check_uuid_in_bdd(SYD_BDD, fields[i][1]);
                if ( check == 1) {
                    if (DEBUG == 1) { printf(" %s est dans la BDD client\n", fields[i][1]); }  
                    strncpy(SYD_PARAMS.state, fields[i][0], sizeof(SYD_PARAMS.state));
                    strncpy(SYD_PARAMS.uuid, fields[i][1], sizeof(SYD_PARAMS.uuid));
                    strncpy(SYD_PARAMS.B, fields[i][2], sizeof(SYD_PARAMS.B));
                    strncpy(SYD_PARAMS.A, fields[i][3], sizeof(SYD_PARAMS.A));
                    strncpy(SYD_PARAMS.g, fields[i][4], sizeof(SYD_PARAMS.g));
                    if (DEBUG == 1) { printf(" |Parsing_SYD_user| %s %s \n", SYD_PARAMS.state, SYD_PARAMS.uuid);}
                }    
    }  
    // Mise a jour du CL_UUID
    strncpy(CL_UUID, SYD_PARAMS.uuid, sizeof(CL_UUID));  
}

//------------------------------------------------------------------------------//
// Lecture du fichier SYD pour extraire le client adapté
int Read_SYD_USER(const char *filename) {
     
      if (DEBUG == 1) { 
      printf("------------------------------------------------------------------\n");
      printf(" |Read_SYD_USER| \n");
      printf(" |Read_SYD_USER| Balise 1 \n");
      }
  // Declaration des variables
    struct JsonValues jvals;

  // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_json = Read_json(filename, &jvals);
    if ( ret_Read_json != 0 ) {
        Write_log(LOG_FILE, "OpenSYD:10: SYD read error");
        return ret_Read_json;
    }
    

    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |Read_SYD_USER| \n");
        printf(" |Read_SYD_USER| Balise 2 \n");
        Display_json(&jvals); 
    }

    char user[SIZE_BUFFER];
    memset(user, '\0', sizeof(user) );
    memset(USERS, '\0', sizeof(USERS) ); // mise en cache pour la creation du fichier tampon



        // lecture des valeurs jvals de X P et TAG
        for (size_t i = 0; i < jvals.entry_count; i++) {
            if (DEBUG == 1) {printf(" |Read_SYD_USER| i : %ld/%ld|\n", i, jvals.entry_count);
                printf(" |Read_SYD_USER| Key : %s|\n", jvals.entries[i].key);
            }   
         if (strcmp(jvals.entries[i].key, "SYD") == 0) {
              size_t longueuruuid = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(SYD_UUID, longueuruuid, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Read_SYD_USER| UUID: %s|\n", SYD_UUID);}   
        } else if (strcmp(jvals.entries[i].key, "USER") == 0) {
              size_t longueuruser = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(user, longueuruser, "%s", jvals.entries[i].value);
              snprintf(USERS, longueuruser, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Read_SYD_USER| USER: %s|\n", user);}   
        } 
        }
    

    // Creation du chemin de lecture de la BDD
    sprintf(SYD_BDD, "%s%s.bdd", BDD_PATH, SYD_UUID);
    
    // Libération de la mémoire
    Free_json_values(&jvals);
    

    
    // Lecture des CL contenus dans users
    Parsing_SYD_user(user);

    return 0;
}

//------------------------------------------------------------------------------//
// Lecture du fichier SYD pour extraire les données
int Read_SYD_DATA(const char *filename) {
     
      if (DEBUG == 1) { 
      printf("------------------------------------------------------------------\n");
      printf(" |Read_SYD_DATA| \n");
      }
  // Declaration des variables
    struct JsonValues jvals;

  // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_json = Read_json(filename, &jvals);
    if ( ret_Read_json != 0 ) {
        Write_log(LOG_FILE, "OpenSYD:10: SYD read error");
        return ret_Read_json;
    }
    
    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |Read_SYD_DATA| \n");
        Display_json(&jvals); 
    }

    memset(DATA, '\0', sizeof(DATA));
    memset(TAG, '\0', sizeof(TAG));
    memset(FILENAME, '\0', sizeof(FILENAME));

        // lecture des valeurs jvals de DATA, FILENAME et TAG
        for (size_t i = 0; i < jvals.entry_count; i++) {
            if (DEBUG == 1) {printf(" |Read_SYD_DATA| i : %ld/%ld|\n", i, jvals.entry_count);
                printf(" |Read_SYD_DATA| Key : %s|\n", jvals.entries[i].key);
            }   
         if (strcmp(jvals.entries[i].key, "DATA") == 0) {
              size_t longueurDATA = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(DATA, longueurDATA, "%s", jvals.entries[i].value);   
        } else if (strcmp(jvals.entries[i].key, "TAG") == 0) {
              size_t longueurTAG = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(TAG, longueurTAG, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Read_SYD_DATA| TAG: %s|\n", TAG);}   
        } else if (strcmp(jvals.entries[i].key, "FILENAME") == 0) {
              size_t longueurFILENAME = strlen(jvals.entries[i].value) + 1;               // Taille de la chaine de caractere              
              snprintf(FILENAME, longueurFILENAME, "%s", jvals.entries[i].value);
              if (DEBUG == 1) {printf(" |Read_SYD_DATA| FILENAME: %s|\n", FILENAME);}   
        }
        }
    
        Free_json_values(&jvals);

    return 0;
}

//------------------------------------------------------------------------------// 
// Transfert de GMP à Chaine de caractères

int Gmp_to_char(mpz_t large_number, char chaine[SIZE_BUFFER] ) {
    // Vérifie la taille du buffer avant d'effectuer l'opération
    if (gmp_snprintf(NULL, 0, "%Zd", large_number) >= SIZE_BUFFER) {
        Write_log(LOG_FILE, "Gmp_to_char:12:MEMORY_ALLOC_ERROR char to small");
        return 12; // Code d'erreur pour indiquer que la chaîne est trop petite
    }

    // Conversion
    int result = gmp_sprintf(chaine, "%Zd", large_number);
    if (result < 0) {
        Write_log(LOG_FILE, "Gmp_to_char:1:GMP_sprintf ERROR");
        return 1; // Code d'erreur pour indiquer que gmp_sprintf a échoué
    }

    /*if (DEBUG == 1) { // Dev Debug
          printf(" |Gmp_to_char| mpz : "); mpz_out_str(stdout, 10, large_number); printf("\n");
          printf(" |Gmp_to_char| char : %s\n", chaine);
    }*/
    return 0; 
}

//------------------------------------------------------------------------------// 
// Transfert de Chaine de caractères à GMP

int Char_to_gmp(char chaine[SIZE_BUFFER], mpz_t large_number) {

    // Vérifie la taille du buffer 
    if (mpz_set_str(large_number, chaine, 10) != 0) {
        Write_log(LOG_FILE, "Char_to_gmp:1:CONVERSION ERROR");
        return 1; // Code d'erreur pour indiquer que la conversion n'a pas marchée
    }
    /*    if (DEBUG == 1) { // Dev Debug
          printf(" |Char_to_gmp| char : %s\n", chaine);
          printf(" |Char_to_gmp| mpz : "); mpz_out_str(stdout, 10, large_number); printf("\n");
          } */
    return 0; // Succès
}

//------------------------------------------------------------------------------// 
// Calcul des clefs pour le chiffrement
// Fonction pour effectuer le calcul Diffie-Hellman

int Clef_KBx(struct DHParameters *params) {

    char KBx_buffer[SIZE_BUFFER]; // afficher en mode debug 
    
    // Vérification de l'initialisation de A, z et p
if (mpz_sgn(params->B) == 0 || mpz_sgn(params->x) == 0 || mpz_sgn(params->p) == 0) {
        Write_log(LOG_FILE, "KEY_KBx:11:B, x or p NULL");
        return 11;
    }
 
  // Calcul KBx 
    mpz_powm(params->KBx, params->B, params->x, params->p);

    if (DEBUG == 1) { 
      Gmp_to_char(params->KBx, KBx_buffer);
      printf(" |Clef_KBx| KBx %s \n", KBx_buffer);
    }

return 0; // OK
}

//------------------------------------------------------------------------------// 
// Fonction d'enrolement du client au service 
//------------------------------------------------------------------------------// 

int SYD_EnrollClient() {

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_EnrollClient| Current Time: %s\n", TIMEBUFFER);
    }
    // Initialisation des structures
        Initialize_ServerConf(&SVR_SYD_CONF_PARAMS);
    // Lecture du fichier de configuration pour charger les elements de configuration du serveur SYD
        char path_file_server[1024];
        memset(path_file_server, '\0', sizeof(path_file_server));
        sprintf(path_file_server, "%s%s", CONFIG_PATH, CONFIG_FILE_SYD);
        int ret_Read_conf_serv = Read_config_server(path_file_server, &SVR_SYD_CONF_PARAMS);
        if ( ret_Read_conf_serv != 0) { Write_log(LOG_FILE, "EnrollClient:10:READ Config server ERROR");}
        
        char path_file_client[1024];
        memset(path_file_client, '\0', sizeof(path_file_client));
        sprintf(path_file_client, "%s%s", CONFIG_PATH, CONFIG_FILE_C);
        int ret_Read_conf_client = Read_config_client(path_file_client);
        if ( ret_Read_conf_client != 0) { Write_log(LOG_FILE, "EnrollClient:10:READ Config client ERROR");}
    // Creation de la requete JSON a envoyer au serveur
    
        // Creation du secret pour la requete
        Generation_chaine(REQUESTKEY, 32);
    
    // Creation de la requete en fonction du type
        char json_data[256];
        Create_Req_JSON(json_data);
    
    // Envoi de la requete au serveur
    
        Send_post(SVR_SYD_CONF_PARAMS.IP, SVR_SYD_CONF_PARAMS.PORT, url, json_data);
    // Recuperation de la requete et retrait de l'entete HTTP
        Copy_json_rply_to_char();
        
    // Lecture et attribution des valeurs à la structure
        Read_reply();
    
    // Ecriture de la bdd locale avec les éléments
    
        char path_file_bdd[1024];
        memset(path_file_bdd, '\0', sizeof(path_file_bdd));
        sprintf(path_file_bdd, "%s%s.bdd", BDD_PATH, SERVER_SYD_UUID);
    
    // Ajout des variables dans la BDD pour que le serveur les utilises
        int ret_wsyd = Write_SYD(path_file_bdd, &SYD_PARAMS);
          if ( ret_wsyd != 0) {
           return ret_wsyd;
          }
    
    // Creation du fichier de reference SP ou CL créé
        Write_Ref(&SYD_PARAMS); 
        
        return 0;
}

//------------------------------------------------------------------------------// 
// Fonction de souscription du client au service 
//------------------------------------------------------------------------------//
int SYD_SubscribeService() {
    
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| Current Time: %s\n", TIMEBUFFER);
    }

    // Initialisation des structures
    Initialize_ServerConf(&SVR_SP_CONF_PARAMS);
    Initialize_ServerConf(&SVR_SYD_CONF_PARAMS);
    Initialize_SYD(&SYD_PARAMS);
    // Lecture des fichiers de configuration
    
    // Lire l'UUID du server SYD de référence
    char path_file_syd_server[1024];
    snprintf(path_file_syd_server, sizeof(path_file_syd_server), "%s%s", CONFIG_PATH, CONFIG_FILE_SYD);
    if (Read_config_server(path_file_syd_server, &SVR_SYD_CONF_PARAMS) != 0) {
        Write_log(LOG_FILE, "SubscribeService:10:READ Config server SYD ERROR");
    }
    sprintf(SYD_UUID, "%s", SVR_SYD_CONF_PARAMS.uuid);
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| SYD UUID : %s\n", SYD_UUID);

    }

    // Lire l'IP et le port du serveur de service
    char path_file_sp_server[1024];
    snprintf(path_file_sp_server, sizeof(path_file_sp_server), "%s%s", CONFIG_PATH, CONFIG_FILE_SP);
    if (Read_config_server(path_file_sp_server, &SVR_SP_CONF_PARAMS) != 0) {
        Write_log(LOG_FILE, "SubscribeService:10:READ Config server SP ERROR");
    }
    
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| SP IP : %s\n", SVR_SP_CONF_PARAMS.IP);
        printf(" |SYD_SubscribeService| SP PORT : %s\n", SVR_SP_CONF_PARAMS.PORT);
        printf(" |SYD_SubscribeService| SP url : %s\n", url);
    }
    // Avec l'UUID du serveur SYD aller chercher l'UUID en cours du Client
    // ouvrir le serverSYD.CL et lire le CL_UUID
    char path_file_client_uuid[1024];
    snprintf(path_file_client_uuid, sizeof(path_file_client_uuid), "%s%s.CL", CONFIG_PATH, SVR_SYD_CONF_PARAMS.uuid);
    if (Read_uuid_client(path_file_client_uuid) != 0) {
        Write_log(LOG_FILE, "SubscribeService:10:READ UUID client ERROR");
    }

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| CL UUID : %s\n", CL_UUID);

    }
    // Lire la BDD locale et sortir la ligne associée avec CL_UUID
    char path_file_client_bdd[1024];
    snprintf(path_file_client_bdd, sizeof(path_file_client_bdd), "%s%s.bdd", BDD_PATH, SVR_SYD_CONF_PARAMS.uuid);
    if (Read_BDD(path_file_client_bdd,SYD_PARAMS.state, CL_UUID, SYD_PARAMS.date, SYD_PARAMS.p, SYD_PARAMS.x, SYD_PARAMS.g ) != 0) { // usage de g pour le tag
        Write_log(LOG_FILE, "SubscribeService:10:READ BDD ERROR");
    }
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| CL P : %s\n", SYD_PARAMS.p);
    }
    // Créer le JSON de souscription pour l'envoyer
    char json_data[2048];
    Create_Subs_JSON(&SYD_PARAMS, json_data);
    
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| SP IP : %s\n", SVR_SP_CONF_PARAMS.IP);
        printf(" |SYD_SubscribeService| SP PORT : %s\n", SVR_SP_CONF_PARAMS.PORT);
        printf(" |SYD_SubscribeService| SP url : %s\n", url);
        printf(" |SYD_SubscribeService| SUBS JSON : %s\n", json_data);
    }
    
    Send_post(SVR_SP_CONF_PARAMS.IP, SVR_SP_CONF_PARAMS.PORT, url, json_data);
    Copy_json_rply_to_char();
    
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| SUBS ret : %s\n", JSON_RESPONSE);
    }
    // Analyse des codes erreurs en retours

    int ret_Detect_error = Detect_error(JSON_RESPONSE);
    
    
    // Liberation de la mémoire
    Free_ServerConf(&SVR_SYD_CONF_PARAMS);
    Free_ServerConf(&SVR_SP_CONF_PARAMS);
    Free_SYD(&SYD_PARAMS);
    memset(json_data, '\0', sizeof(json_data));
    memset(JSON_RESPONSE, '\0', sizeof(JSON_RESPONSE));
    
    return ret_Detect_error;

}

//------------------------------------------------------------------------------// 
// Fonction de demande d'un TANK au service provider
//------------------------------------------------------------------------------// 
int SYD_AskNewService() {

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        if (NB_UUID > 0) {
          for (size_t i = 0; i < NB_UUID ; i++) {
            printf(" |SYD_AskNewService| UUIDs recus : %s\n", LIST_UUID[i]);
          }  
        } else {
        printf(" |SYD_AskNewService| Aucun UUIDs reçus\n");
        }
    }
    // Initialisation des structures
    Initialize_ServerConf(&SVR_SP_CONF_PARAMS);
    Initialize_SYD(&SYD_PARAMS);
    
    // Lire l'UUID du server SYD de référence
    char path_file_syd_server[1024];
    snprintf(path_file_syd_server, sizeof(path_file_syd_server), "%s%s", CONFIG_PATH, CONFIG_FILE_SYD);
    if (Read_config_server(path_file_syd_server, &SVR_SYD_CONF_PARAMS) != 0) {
        Write_log(LOG_FILE, "AskNewService:10:READ Config server SYD ERROR");
    }
    sprintf(SYD_UUID, "%s", SVR_SYD_CONF_PARAMS.uuid);
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_AskNewService| SYD UUID : %s\n", SYD_UUID);
    }

    // Lire l'IP et le port du serveur de service
    char path_file_sp_server[1024];
    snprintf(path_file_sp_server, sizeof(path_file_sp_server), "%s%s", CONFIG_PATH, CONFIG_FILE_SP);
    if (Read_config_server(path_file_sp_server, &SVR_SP_CONF_PARAMS) != 0) {
        Write_log(LOG_FILE, "AskNewService:10:READ Config server SP ERROR");
    }
    
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_AskNewService| SP IP : %s\n", SVR_SP_CONF_PARAMS.IP);
        printf(" |SYD_AskNewService| SP PORT : %s\n", SVR_SP_CONF_PARAMS.PORT);
        printf(" |SYD_AskNewService| SP url : %s\n", url);
    }

    // Avec l'UUID du serveur SYD aller chercher l'UUID en cours du Client
    // ouvrir le serverSYD.CL et lire le CL_UUID
    char path_file_client_uuid[1024];
    snprintf(path_file_client_uuid, sizeof(path_file_client_uuid), "%s%s.CL", CONFIG_PATH, SVR_SYD_CONF_PARAMS.uuid);
    if (Read_uuid_client(path_file_client_uuid) != 0) {
        Write_log(LOG_FILE, "AskNewService:10:READ UUID client ERROR");
    }

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_AskNewService| CL UUID : %s\n", CL_UUID);

    }

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_AskNewService| CL UUID : %s\n", CL_UUID);
        printf(" |SYD_AskNewService| CL P : %s\n", SYD_PARAMS.p);
    }
    // Créer le JSON de souscription pour l'envoyer
    char json_data[2048];
    Create_TANK_JSON(json_data);
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| SUBS JSON : \n%s\n", json_data);
    }
    Send_post(SVR_SP_CONF_PARAMS.IP, SVR_SP_CONF_PARAMS.PORT, url, json_data);
    Copy_json_rply_to_char();

    // Vérification que le retour ne soit pas une erreur 
    int ret_Detect_error = Detect_error(JSON_RESPONSE);
    if ( ret_Detect_error !=0 ){
        return ret_Detect_error;
    }

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |SYD_SubscribeService| SUBS ret : \n%s\n", JSON_RESPONSE);
    }
    // ecriture du fichier SyD à l'emplacement souhaité
    Write_SYDFILE();
    
    // Effacement des espaces mémoires alloués
    Free_ServerConf(&SVR_SP_CONF_PARAMS);
    Free_SYD(&SYD_PARAMS);
    memset(json_data, '\0', sizeof(json_data));
    memset(JSON_RESPONSE, '\0', sizeof(JSON_RESPONSE));

    return 0; // succès
}

//------------------------------------------------------------------------------// 
// Fonction d'ouverture d'un SYD
//------------------------------------------------------------------------------// 

int SYD_OpenSYD() {
    Get_current_time(TIMEBUFFER, sizeof(TIMEBUFFER));
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| Current Time: %s\n", TIMEBUFFER);
    }

    // Declaration des variables de la fonction  
    char encrypted_base64[SIZE_BUFFER];
    char tag[64];
    unsigned char decrypted_x[SIZE_X];
    unsigned char shared_key[SIZE_X];
    unsigned char hash_Key[SHA256_DIGEST_LENGTH];
    unsigned char iv[12];  // IV basé sur le 12 permiers caractères de P
    
    // Initialisation des variables de la fonction
    memset(encrypted_base64, '\0', SIZE_BUFFER);
    memset(tag, '\0', 64);
    memset(iv, '\0', sizeof(iv));
    
    // Initialisation des structures
    Initialize_SYD(&SYD_PARAMS);
    
 
    // Ouvrir le JSON SYD, Collecter la valeur du SYD_UUID
    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| Read SYD\n");
    }

    if (DEBUG == 1) { printf(" |OpenSYD| lecture fichier %s\n", SYDFILE );}
    // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_SYD_user = Read_SYD_USER(SYDFILE);
    if ( ret_Read_SYD_user!= 0 ) {
        if (DEBUG == 1) { printf(" |OpenSYD| Error %d file %s\n",ret_Read_SYD_user, SYDFILE);}
        Write_log(LOG_FILE, "OpenSYD:10:SYD file read error");
        return 10;
    }
    if (DEBUG == 1) { Display_SYD(&SYD_PARAMS);
        printf(" |OpenSYD| UUID ServerSYD : %s\n",SYD_UUID);
        printf(" |OpenSYD| UUID CL        : %s\n", SYD_PARAMS.uuid);
    }

    // Lire la BDD locale et sortir la ligne associée avec CL_UUID

    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| Read Local BDD\n");
    }

    char path_file_client[SIZE];
    snprintf(path_file_client, sizeof(path_file_client), "%s%s", CONFIG_PATH, CONFIG_FILE_C);
    if (Read_config_client(path_file_client) != 0) {
        Write_log(LOG_FILE, "OpenSYD:10:READ Config client ERROR");
    }

    sprintf(SYD_BDD, "%s%s.bdd", BDD_PATH, SYD_UUID);

    if (Read_BDD(SYD_BDD,SYD_PARAMS.state, CL_UUID, SYD_PARAMS.date, SYD_PARAMS.p, SYD_PARAMS.x, tag ) != 0) { // usage de g pour le tag et A pour la donnee chiffrée
        Write_log(LOG_FILE, "OpenSYD:10:READ Client BDD ERROR");
    }
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| CL UUID : %s\n", CL_UUID);
        printf(" |OpenSYD| CL p : %s\n", SYD_PARAMS.p);
        printf(" |OpenSYD| Encrypted x : %s\n", SYD_PARAMS.x);
        printf(" |OpenSYD| tag : %s\n", tag);
    }

    // Dechiffrer les valeurs lues dans la BDD
        // Calcul de la clef pour dechiffrer x
       if ( sha256(CLIENTKEY, hash_Key) != 0) {
            if (DEBUG == 1) {
                printf(" |OpenSYD| SHA256 : Echec du hash !\n");
            }
            return 14;
        }
        
        //Creation de l'iv
        strncpy((char *)iv, SYD_PARAMS.p, 12);
        
        int decrypted_x_len = decrypt_AES_GCM_base64(SYD_PARAMS.x, tag, hash_Key, iv, decrypted_x);
        if (decrypted_x_len >= 0) {
            decrypted_x[decrypted_x_len] = '\0';
            if (DEBUG == 1) {
                printf("------------------------------------------------------------------\n");
                printf(" |OpenSYD| CL x : %s\n", decrypted_x);
            }

        } else {
            if (DEBUG == 1) {
                printf(" |OpenSYD| Lecture de x : Echec du dechiffrement !\n");
            }
            return 20;
        }
        // transfert de la clef dans la structure
        strncpy(SYD_PARAMS.x, (char *)decrypted_x, sizeof(SYD_PARAMS.x));
        if (DEBUG == 1) {
                printf("------------------------------------------------------------------\n");
                printf(" |OpenSYD| CL UUID : %s\n", CL_UUID);
                printf(" |OpenSYD| CL p : %s\n", SYD_PARAMS.p);
                printf(" |OpenSYD| CL x : %s\n", SYD_PARAMS.x);
            }
    // Initialisation du calcul de la clef KBx
    struct DHParameters DH_PARAMS;
    Initialize_dh_parameters(&DH_PARAMS);

    // Transfert des variables en GMP lue dans la BDD dans DHParams
    Char_to_gmp(SYD_PARAMS.B, DH_PARAMS.B);
    Char_to_gmp(SYD_PARAMS.p, DH_PARAMS.p);
    Char_to_gmp(SYD_PARAMS.x, DH_PARAMS.x);
     // Calculer la clef associée avec l'UUID
     if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| Calcul de KBx\n");
    }
    int ret_calc_KBx = Clef_KBx(&DH_PARAMS);
    if ( ret_calc_KBx != 0) {  
          return 11;
        } 

    // Dechiffrer la clef de dechiffrement des DATA
    char temp[SIZE_BUFFER];
    Gmp_to_char(DH_PARAMS.KBx, temp);
    memset(hash_Key, '\0', sizeof(hash_Key));
        if ( sha256(temp, hash_Key) != 0) {
          Write_log(LOG_FILE, "SP:14:HASH_CORRUPTION");  
          return 14;
        }    

    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| Dechiffrement de SYDKEY\n");
    }
    memset(iv, '\0', sizeof(iv));
    strncpy((char *)iv, SYD_PARAMS.B, 12);
    memset(shared_key, '\0', sizeof(shared_key));
    int decrypted_sh_key_len = decrypt_AES_GCM_base64(SYD_PARAMS.A, SYD_PARAMS.g, hash_Key, iv, shared_key);
        if (decrypted_sh_key_len >= 0) {
            shared_key[decrypted_sh_key_len] = '\0';
            if (DEBUG == 1){printf("Shared Key %s\n",(unsigned char *)shared_key);}
        } else {
            Write_log(LOG_FILE, "OpenSYD:20:UNCIPHER_FAIL Shared Key");
            printf("Erreur Shared Key\n");
            return 20;
        }

    // -----------------------------------------------------------------------------
    // Partie de la fonction qui permet de traiter les données chiffrées dans le SYD

    // Lecture de DATA (char en base64)
    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| Lecture des donnees\n");
    }
    Read_SYD_DATA(SYDFILE);

    // Verifier si DATA Null
    if ( DATA[0] != '\0' ) {

        // Recuperation de l'IV 
        memset(iv, '\0', sizeof(iv));
        strncpy((char *)iv, SYD_UUID, 12);
        // Copie en memoire dans le bon format de la clef partagée
        memset(hash_Key, '\0', sizeof(hash_Key));
        char signed_shared_key[SIZE_X];
        memcpy(signed_shared_key, shared_key, sizeof(shared_key));

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |OpenSYD| Unsigned Shared_key |%s|\n", shared_key);
        printf(" |OpenSYD| Signed Shared Key  |%s|\n", signed_shared_key);
        printf(" |OpenSYD| iv |%s|\n", iv);
        //printf(" |OpenSYD| DATA |%s|\n", DATA); // Ne pas décommenter en qualification avec des fichiers de grosse taille
        printf(" |OpenSYD| TAG |%s|\n", TAG);
        //printf(" |OpenSYD| OPENED SYD |%s|\n", tmp_syd);
    }
        // Calcul du hash de la clef partagée
        if ( sha256(signed_shared_key, hash_Key) != 0) {
          Write_log(LOG_FILE, "SP:14:HASH_CORRUPTION");  
          return 14;
        }
        // Déchiffrement de de DATA  
        int decrypted_DATA_len = decrypt_AES_GCM_base64(DATA, TAG, hash_Key, iv, (unsigned char *)UNCIPHER_DATA);
        if (decrypted_DATA_len >= 0) {
                    if (DEBUG == 1) {
                        printf("------------------------------------------------------------------\n");
                        printf(" |OpenSYD| Data length |%d|\n", decrypted_DATA_len);
                        }
        } else {
            Write_log(LOG_FILE, "OpenSYD:20:UNCIPHER_FAIL File not uncipher");
            return 20;
        }
       
        char tmp_out_path_file[SIZE];
        snprintf(tmp_out_path_file, SIZE, "%s/%s", PATH_OUT_FILE, FILENAME);

        FILE *fichier = fopen(tmp_out_path_file, "wb");  // mode "w" pour écraser, "a" pour ajouter
        
        if (fichier == NULL) {
            Write_log(LOG_FILE, "OpenSYD:10:Unable to write DATA");
            return 10;
        }
        
        fwrite(UNCIPHER_DATA, 1, decrypted_DATA_len, fichier);
        fclose(fichier);
    } else {
            if (DEBUG == 1) {
                printf("------------------------------------------------------------------\n");
                printf(" |OpenSYD| DATA vide\n");
            }
            return 0;
    }
    // Effacement des espaces mémoires alloués
    Free_SYD(&SYD_PARAMS);

    return 0;
}

//------------------------------------------------------------------------------// 
// Fonction de fermeture d'un SYD
//------------------------------------------------------------------------------// 
int SYD_CloseSYD() {

// Calculer la clef
        Get_current_time(TIMEBUFFER, sizeof(TIMEBUFFER));
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |CloseSYD| Current Time: %s\n", TIMEBUFFER);
        printf(" |CloseSYD| filename: %s\n", SYDFILE);
    }

    // Declaration des variables de la fonction 
    char tag[64];
    unsigned char decrypted_x[SIZE_X];
    unsigned char shared_key[SIZE_X];
    unsigned char hash_Key[SHA256_DIGEST_LENGTH];
    unsigned char iv[12];  // IV basé sur le 12 permiers caractères de P
    
    // Initialisation des variables de la fonction
    
    memset(tag, '\0', 64);
    memset(iv, '\0', sizeof(iv));
    // Initialisation des structures
    Initialize_SYD(&SYD_PARAMS);
    

    // Ouvrir le JSON SYD, Collecter la valeur du SYD_UUID
    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |CloseSYD| Read SYD\n");
    }

    if (DEBUG == 1) { printf(" |CloseSYD| lecture fichier %s\n", SYDFILE );}
    // Lecture des fichiers de configuration avec l'usage de la lecture de fichier JSON
    int ret_Read_SYD_user = Read_SYD_USER(SYDFILE);
    if ( ret_Read_SYD_user!= 0 ) {
        if (DEBUG == 1) { printf(" |CloseSYD| Error %d file %s\n",ret_Read_SYD_user, SYDFILE);}
        Write_log(LOG_FILE, "CloseSYD:10:SYD file read error");
        return 10;
    }
    if (DEBUG == 1) { Display_SYD(&SYD_PARAMS);
        Write_log(LOG_FILE, SYD_UUID);
        Write_log(LOG_FILE, SYD_PARAMS.uuid);
    }

    // Lire la BDD locale et sortir la ligne associée avec CL_UUID

    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |CloseSYD| Read Local BDD\n");
    }

    char path_file_client[SIZE];
    snprintf(path_file_client, sizeof(path_file_client), "%s%s", CONFIG_PATH, CONFIG_FILE_C);
    if (Read_config_client(path_file_client) != 0) {
        Write_log(LOG_FILE, "CloseSYD:10:READ Config client ERROR");
    }

    sprintf(SYD_BDD, "%s%s.bdd", BDD_PATH, SYD_UUID);

    if (Read_BDD(SYD_BDD,SYD_PARAMS.state, CL_UUID, SYD_PARAMS.date, SYD_PARAMS.p, SYD_PARAMS.x, tag ) != 0) { // usage de g pour le tag et A pour la donnee chiffrée
        Write_log(LOG_FILE, "CloseSYD:10:READ Client BDD ERROR");
    }
    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |CloseSYD| CL UUID : %s\n", CL_UUID);
        printf(" |CloseSYD| CL p : %s\n", SYD_PARAMS.p);
        printf(" |CloseSYD| Encrypted x : %s\n", SYD_PARAMS.x);
        printf(" |CloseSYD| tag : %s\n", tag);
    }

    // Dechiffrer les valeurs lues dans la BDD
        // Calcul de la clef pour dechiffrer x
       if ( sha256(CLIENTKEY, hash_Key) != 0) {
            if (DEBUG == 1) {
                printf(" |CloseSYD| SHA256 : Echec du hash !\n");
            }
            return 14;
        }
        
        //Creation de l'iv
        strncpy((char *)iv, SYD_PARAMS.p, 12);
        
        int decrypted_x_len = decrypt_AES_GCM_base64(SYD_PARAMS.x, tag, hash_Key, iv, decrypted_x);
        if (decrypted_x_len >= 0) {
            decrypted_x[decrypted_x_len] = '\0';
            if (DEBUG == 1) {
                printf("------------------------------------------------------------------\n");
                printf(" |CloseSYD| CL x : %s\n", decrypted_x);
            }

        } else {
            if (DEBUG == 1) {
                printf(" |CloseSYD| Lecture de x : Echec du dechiffrement !\n");
            }
            return 20;
        }
        // transfert de la clef dans la structure
        strncpy(SYD_PARAMS.x, (char *)decrypted_x, sizeof(SYD_PARAMS.x));
        if (DEBUG == 1) {
                printf("------------------------------------------------------------------\n");
                printf(" |CloseSYD| CL UUID : %s\n", CL_UUID);
                printf(" |CloseSYD| CL p : %s\n", SYD_PARAMS.p);
                printf(" |CloseSYD| CL x : %s\n", SYD_PARAMS.x);
            }
    // Initialisation du calcul de la clef KBx
    struct DHParameters DH_PARAMS;
    Initialize_dh_parameters(&DH_PARAMS);

    // Transfert des variables en GMP lue dans la BDD dans DHParams
    Char_to_gmp(SYD_PARAMS.B, DH_PARAMS.B);
    Char_to_gmp(SYD_PARAMS.p, DH_PARAMS.p);
    Char_to_gmp(SYD_PARAMS.x, DH_PARAMS.x);
     // Calculer la clef associée avec l'UUID
     if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |CloseSYD| Calcul de KBx\n");
    }
    Clef_KBx(&DH_PARAMS);

    // Dechiffrer la clef de dechiffrement des DATA
    char temp[SIZE_BUFFER];
    Gmp_to_char(DH_PARAMS.KBx, temp);
    
    
    memset(hash_Key, '\0', sizeof(hash_Key));
        if ( sha256(temp, hash_Key) != 0) {
            if (DEBUG == 1) {
                printf(" |CloseSYD| SHA256 : Echec du hash !\n");
            }
        Write_log(LOG_FILE, "CloseSYD:14:HASH_CORRUPTION");  
        return 14;
        }    

    if (DEBUG == 1) { 
        printf("------------------------------------------------------------------\n");
        printf(" |CloseSYD| Dechiffrement de SYDKEY\n");
    }
    memset(iv, '\0', sizeof(iv));
    strncpy((char *)iv, SYD_PARAMS.B, 12);
    memset(shared_key, '\0', sizeof(shared_key));
    int decrypted_sh_key_len = decrypt_AES_GCM_base64(SYD_PARAMS.A, SYD_PARAMS.g, hash_Key, iv, shared_key);
        if (decrypted_sh_key_len >= 0) {
            shared_key[decrypted_sh_key_len] = '\0';
            if (DEBUG == 1) {
                printf(" |CloseSYD| Shared Key %s\n",(unsigned char *)shared_key);
            }
        } else {
            Write_log(LOG_FILE, "CloseSYD:20:UNCIPHER_FAIL Shared Key");
            if (DEBUG == 1) {
                printf(" |CloseSYD| Erreur Shared Key\n");
            }
            return 20;
        }

    // Calcul et preparation du chiffrement du SYD
    memset(iv, '\0', sizeof(iv));
    strncpy((char *)iv, SYD_UUID, 12);
    memset(hash_Key, '\0', sizeof(hash_Key));
    if ( sha256((char *)shared_key, hash_Key) != 0) {
          Write_log(LOG_FILE, "CloseSYD:14:HASH_CORRUPTION");  
          return 14;
    } 
    // Effacement de la clef partagée
    memset(shared_key, '\0', sizeof(shared_key));

    if (DEBUG == 1) {
        printf("------------------------------------------------------------------\n");
        printf(" |CloseSYD| Chiffrement du SYD\n");
        printf(" |CloseSYD| Fichier a chiffrer %s\n", FILENAME);
    }

        char *encrypted_base64 = encrypt_file_AES_GCM_base64(FILENAME, hash_Key, iv, TAG);
        // Effacement IV et hash_key
        memset(iv, '\0', sizeof(iv));
        memset(hash_Key, '\0', sizeof(hash_Key));
        
        // Ecriture du fichier SyD
        // Récuperation du nom du fichier sans le chemin 
        const char *fullpath = FILENAME;
              const char *basename = strrchr(fullpath, '/');
              basename = (basename != NULL) ? basename + 1 : fullpath;
              if (DEBUG == 1) { printf(" |Select_usage| basename %s\n", basename);}
              snprintf(FILENAME, sizeof(FILENAME), "%s", basename);
        
        Write_CloseSYD(SYDFILE, FILENAME ,encrypted_base64);
        
        // Effacement des espaces mémoires alloués
        Free_SYD(&SYD_PARAMS);
        


return 0;
}

//------------------------------------------------------------------------------// 
//-----------------------------------MAIN---------------------------------------//
//------------------------------------------------------------------------------// 
int main(int argc, char *argv[]) {
//------------------------------------------------------------------------------// 
// Initialiser les parametres
    Get_current_time(TIMEBUFFER, sizeof(TIMEBUFFER));
    if (DEBUG == 1) { 
    printf("------------------------------------------------------------------\n");
    printf(" |Main| Current Time: %s\n", TIMEBUFFER);
    }
// Configuration du repertoire d'execution du SyD Client
    
    char *base_dir = Get_executable_dir();

    if ( base_dir != NULL) {
       if ( DEBUG == 1) { printf(" |Main| Chemin absolu : %s\n", base_dir);}
       snprintf(DIR_PATH, sizeof(DIR_PATH), "%s", base_dir);
    } else {
         if ( DEBUG == 1) { printf(" |Main| Erreur de gestion du chemin d'execution\n");}
         Write_log(LOG_FILE, "Main:19:DIRECTORY_ERROR Program execution directory not found");
         return 19;
    }
// Configuration du chemin des repertoires des fichiers BDD et CONF
    snprintf(BDD_PATH, MAX_FILENAME_LEN, "%s%s", DIR_PATH, BDD_DIR);
    if ( DEBUG == 1) { printf(" |Main| Chemin absolu BDD : %s\n", BDD_PATH);}
    snprintf(CONFIG_PATH, MAX_FILENAME_LEN, "%s%s", DIR_PATH, CONFIG_DIR);
    if ( DEBUG == 1) { printf(" |Main| Chemin absolu CONF : %s\n", CONFIG_PATH);}

// Initialiser les structures
    struct ProgParams PROGARGS;
// Collecte du nombre d arguments du programme

  if (DEBUG == 1){
    printf(" |Main| Nombre d'argument recus %d", argc);
  }
   
   if (argc < 2){
     Usage("SyD");
     Write_log(LOG_FILE, "Main:11:INVALID_ARGUMENT");
     return 11;
   }
    PROGARGS.entry_number = argc;

  // Allouer de la memoire pour stocker les arguments
      PROGARGS.values = malloc(argc * sizeof(char *));
      if (PROGARGS.values == NULL) {
          if ( DEBUG == 1) { printf(" |Main| Erreur d'allocation memoire");}
          Write_log(LOG_FILE, "Main:12:MEMORY_ALLOC_ERROR Program table number of values");
          return 12;
      }
  
  // Copie des arguments dans le tableau cree dans la structure ProgParams
      for (size_t i = 0; i < PROGARGS.entry_number; i++) {
          // Allouer de la memoire pour chaque argument
          size_t length = strlen(argv[i]) + 1; // +1 pour le caractere nul
          PROGARGS.values[i] = malloc(length * sizeof(char));
            
          if (PROGARGS.values[i] == NULL) {
              Write_log(LOG_FILE, "Main:12:MEMORY_ALLOC_ERROR Program values size in table");
          // Liberer les allocations precedentes avant de quitter
              for (size_t j = 0; j < i; j++) {
                  free(PROGARGS.values[j]);
              }
              free(PROGARGS.values);
              return 12;
          }
          snprintf(PROGARGS.values[i], length, "%s", argv[i]);
          if (DEBUG == 1){printf(" |Main| PROGARGS : %s\n",PROGARGS.values[i]);}
      }
  
// Selection des usages

    int ret_select_usage = Select_usage(&PROGARGS);
    if ( ret_select_usage == 0 ){
      Usage(PROGARGS.values[0]);
    } else if (ret_select_usage == 1) {
      printf(" Creation d'un SyD \n");
      int ret_AskNewService = SYD_AskNewService();
      if ( ret_AskNewService != 0) {
                printf("Erreur de creation de TANK %d\n", ret_AskNewService);
      }

    } else if (ret_select_usage == 2) {
      int ret_open_syd = SYD_OpenSYD();
      if ( ret_open_syd != 0) {
                  printf("Erreur d'ouverture du SyD %d\n", ret_open_syd);
      }

    } else if (ret_select_usage == 3) {
      int ret_close_syd = SYD_CloseSYD();
      if ( ret_close_syd != 0) {                 
                  printf("Erreur d'enregistrement du SyD %d\n", ret_close_syd);
      }

    } else if (ret_select_usage == 4) {
      int ret_enrol_client = SYD_EnrollClient();
      if ( ret_enrol_client != 0) {
                  printf("Erreur d'enrolement %d\n", ret_enrol_client);
      }

    } else if (ret_select_usage == 5) {
      int ret_subs_client = SYD_SubscribeService();
      if ( ret_subs_client == 201 ) {
            printf("Souscription effectuee retour code %d\n", ret_subs_client);
            
      } else if (ret_subs_client == 200 ) { 
            printf("Souscription deja effectuee retour code %d\n", ret_subs_client);
      } else {
             printf("Erreur de souscription code %d\n", ret_subs_client);
      }

    }

// Libération de l'allocation de PROGARG

    for (size_t i = 0; i < PROGARGS.entry_number; i++) {
              free(PROGARGS.values[i]);
          }
          free(PROGARGS.values);
    
  return 0;  
}



