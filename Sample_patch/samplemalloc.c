/*http://stackoverflow.com/questions/1094532/problem-in-overriding-malloc*/
#include<stdio.h>
#include<stdlib.h>
#define malloc(X) my_malloc((X))

void* my_malloc(size_t size)
{

    void *p = malloc(size);
    printf ("Allocated = %s, %s, %s, %x\n",__FILE__, __LINE__, __FUNCTION__, p);
    return p;
}

int main()
{
int *a;
a=malloc(sizeof(int));
return 0;
}
