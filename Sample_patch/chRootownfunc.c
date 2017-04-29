/*reference - http://stackoverflow.com/questions/3946063/howto-enter-into-chroot-environment-from-c
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void chRoot()
{

 char c[100];
 char* command="pwd";
 char* path="";

    FILE *f = popen(command, "r");

    while (fgets(c, 100, f) != NULL) {
        strcat(path,c);
    }

     /* chroot */
     chdir(path);
     if (chroot(path) != 0) {
         printf("chroot %s",path);
         
     }

    pclose(f);

}


