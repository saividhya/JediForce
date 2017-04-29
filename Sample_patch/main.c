#include <stdio.h>
int main (int argc, char **argv)
{
char str[20]="%d %d %d %d %d";
int num,ret;
scanf("%d",&num);
fprintf (stdout,"This is a variable argument message - %s\n", "Rahul Jain");
fprintf (stdout,"This is a static argument message - Rahul Jain\n");
ret=printf ("This is a variable argument message - %d\n", num);
if(ret==5)
return 0;
printf ("This is a static argument message - Rahul Jain\n");
return 0;

}

