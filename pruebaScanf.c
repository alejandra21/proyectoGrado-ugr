#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>



int main(int argc, char *argv[])
{
    /* code */
    char page[200]; // Page field of the uri if found
    char scheme[200]; // Page field of the uri if found
    char query[200]; // Page field of the uri if found
    char fragment[200]; // Page field of the uri if found
    char uri[1000];
    FILE *archivoProcesos;
    char* nombreSalida = argv[1];


    if ( (archivoProcesos=fopen(argv[1],"r")) == NULL ) {

        perror("Error: El archivo indicado no fue encontrado ");
        printf("errno = %d. \n",errno);
        exit(1);
    }

    else {

        archivoProcesos = fopen(argv[1],"r");
        int FinalArchivo = 0;
        while (FinalArchivo == 0) {

            // Se reserva el espacio de memoria para la nueva linea
            fscanf(archivoProcesos," %[^\n]\n" ,uri);

            printf("-----------------------------------------------\n");
            printf("URI :%s\n",uri);
            if (sscanf(uri, "http://%[^?#/]%[^?#]?%[^?#]#%[^#]", page,scheme,query,fragment) == 4) {

                printf("*authority = %s\n", page);
                printf("*path = %s\n", scheme);
                printf("*query = %s\n", query);
                printf("*fragment = %s\n", fragment);
            }
            else if (sscanf(uri, "http://%[^?#/]%[^?#]?%[^?#]", page,scheme,query) == 3) {

                printf("*authority = %s\n", page);
                printf("*path = %s\n", scheme);
                printf("*query = %s\n", query);
            }
            else if (sscanf(uri, "http://%[^?#/]%[^?#]#%[^#]", page,scheme,fragment) == 3){

                printf("*authority = %s\n", page);
                printf("*path = %s\n", scheme);
                printf("*fragment = %s\n", fragment);

            }
            else if (sscanf(uri, "http://%[^?#/]%[^?#]", page,scheme) == 2) {

                printf("*authority = %s\n", page);
                printf("*path = %s\n", scheme);

            }
            else if (sscanf(uri, "http://%[^?#/]", page) == 1) {

                printf("*authority = %s\n", page);

            }
            else if (sscanf(uri, "http://%[^?#]?%[^?#]#%[^#]", scheme,query,fragment) == 3){

                printf("*path = %s\n", scheme);
                printf("*query = %s\n", query);
                printf("*fragment = %s\n", fragment);
            }
            printf("-----------------------------------------------\n");

            // Se verifica si se llego al final del archivo.
            if (feof(archivoProcesos)){
                FinalArchivo = 1;
                fclose(archivoProcesos);    
            }
        }
    }
        
    return 0;
}