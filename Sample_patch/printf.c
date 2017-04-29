/*reference : https://gcc.gnu.org/ml/gcc-help/2009-10/msg00372.html
Build commands (with gcc 342) 
>> /usr/local/soft/gcc/3.4.2/bin/g++ -ggdb -o printf.o -c printf.c
>> /usr/local/soft/gcc/3.4.2/bin/g++ -ggdb -o main.o -c main.c
>> /usr/local/soft/gcc/3.4.2/bin/g++ -ggdb -o a.out printf.o main.o
*/
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
extern "C" int fprintf (FILE *__restrict __stream,
                 __const char *__restrict __format, ...)
{
    int ret_status = 0;
    //printf("Called my version of fprintf\n");
    va_list args;
    va_start(args,__format);
    ret_status = vfprintf(__stream, __format, args);
    va_end(args);
    return ret_status;
}
extern "C" int fputs (__const char *__restrict __s, FILE *__restrict
__stream)
{
     int ret_status = 0;
    // printf("Called my version of fputs\n");
     return fprintf(__stream, "%s", __s);
}

extern "C" int printf (__const char *__restrict __format, ...)
{
    int ret_status = 0;
	char *p;
    int i=0,count=0;
  //  printf ("Called my version of printf\n");
    va_list args,args2;

    va_start(args, __format);
    va_start(args2, __format);

    /*while(1)
	{
		i=0;
		char *argsgiven=(char*)va_arg(args,char*);
		if(argsgiven == NULL)
		{break;}
		else
		{p=strstr(argsgiven,"%d");
		if(p)
		count++;
		}
		
	}
    if(count>0)
	{
		ret_status=5;
	}
	else
   {*/ret_status = vprintf(__format, args);//}
    va_end(args);
    return ret_status;
}
extern "C" int puts (__const char *__s)
{
    int ret_status = 0;
//printf ("Called my version of puts\n");
    return printf("%s\n", __s);
}
