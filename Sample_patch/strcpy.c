/*reference-http://stackoverflow.com/questions/9107259/how-to-replace-c-standard-library-function
https://en.wikibooks.org/wiki/C_Programming/C_Reference/stdio.h/gets
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char* gets(char *s)
{
    char * ch = s;
    int k;
	int len=sizeof(s);	
	    
    /* until we read a newline */
    while ((k = getchar ()) != '\n') {
 	
        if (k == EOF) {
            /* EOF at start of line or errors other than EOF return NULL */
            if (ch == s || !feof(stdin)) 
                return NULL;

            break;
        }
		
        /* character is stored at address, and pointer is incremented */
	if((len-1)>strlen(ch))
        *ch++ = (char)k;
	else
	{
		printf("Get out hacker");
		exit(0);
	}
    }
		
    /* Null-terminating character added */
    *ch = '\0';
		
    /* return original pointer */
    return s; 
}


char * strcpy(char *dst, const char *src)
{
  if(strlen(src)>=sizeof(src))
	{
		printf("Get out Hacker!");
		exit(0);
	}
  if(strlen(src)>=sizeof(dst))
	{
		printf("Get out Hacker!");
		exit(0);
	}
  char *d = dst;
  while (*src) {
    *d = *src;
    d++;
    src++;
  }
  printf("Called my strcpy()\n");

  return (dst);
}

char* strncpy(char *dst, const char* src, size_t n)
{
   if(sizeof(dst)<=n)
	{
		printf("Get out Hacker!");
		exit(0);
  	}
  
    if ((dst == NULL) || (src == NULL))
         return NULL;
    size_t i;
    for(i = 0; i < n && src[i] != '\0'; ++i)
         dst[i] = src[i];
    for(; i < n; ++i)
         dst[i] = '\0';
    return dst;
}


