#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>

int main(int argc, char **argv)
{
   int i = 0;
   int res;
   int len;
   char result[BUFSIZ];
   char err_buf[BUFSIZ];
   char* src = argv[1];  

   const char* pattern = "([Hh][Tt][Tt][Pp][Ss]:)?(//([^/?#]*))?([^?#]*)([/?][^#]*)?(#(.*))?";

   regex_t preg;

   regmatch_t pmatch[10];

   if( (res = regcomp(&preg, pattern, REG_EXTENDED)) != 0)
   {
      regerror(res, &preg, err_buf, BUFSIZ);
      printf("regcomp: %s\n", err_buf);
      exit(res);
   }

   res = regexec(&preg, src, 10, pmatch, REG_NOTBOL);
   //~ res = regexec(&preg, src, 10, pmatch, 0);
   //~ res = regexec(&preg, src, 10, pmatch, REG_NOTEOL);
   if(res == REG_NOMATCH)
   {
      printf("NO match\n");
      exit(0);
   }
   for (i = 0; pmatch[i].rm_so != -1; i++)
   {
      len = pmatch[i].rm_eo - pmatch[i].rm_so;
      memcpy(result, src + pmatch[i].rm_so, len);
      result[len] = 0;
      printf("num %d: '%s'\n", i, result);
   }
   regfree(&preg);
   return 0;
}