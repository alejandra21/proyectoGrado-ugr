#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>



int main(int argc, char const *argv[])
{
    /* code */
    char page[200]; // Page field of the uri if found
    char scheme[200]; // Page field of the uri if found
    char query[200]; // Page field of the uri if found
    char fragment[200]; // Page field of the uri if found
    char* rot13 = "/?manifestacion=Pinturas+Rupestres&pepe=/#pepe";


    if (sscanf(rot13, "/%[^?#/]%[^?#]?%[^?#]#%[^#]", page,scheme,query,fragment) == 4) {

        printf("*authority = %s\n", page);
        printf("*path = %s\n", scheme);
        printf("*query = %s\n", query);
        printf("*fragment = %s\n", fragment);
    }
    else if (sscanf(rot13, "/%[^?#/]%[^?#]?%[^?#]", page,scheme,query) == 3) {

        printf("*authority = %s\n", page);
        printf("*path = %s\n", scheme);
        printf("*query = %s\n", query);
        printf("*fragment = %s\n", fragment);
    }
    else if (sscanf(rot13, "/%[^?#/]%[^?#]", page,scheme) == 2) {

        printf("*authority = %s\n", page);
        printf("*path = %s\n", scheme);
        printf("*query = %s\n", query);
        printf("*fragment = %s\n", fragment);
    }
    else if (sscanf(rot13, "/%[^?#/]%[^?#]#%[^#]", page,scheme,fragment) == 3){

        printf("*authority = %s\n", page);
        printf("*path = %s\n", scheme);
        printf("*fragment = %s\n", fragment);

    }
    else if (sscanf(rot13, "%[^?#]?%[^?#]#%[^#]", scheme,query,fragment) == 3){

        printf("*path = %s\n", scheme);
        printf("*query = %s\n", query);
        printf("*fragment = %s\n", fragment);
    }
        
    return 0;
}