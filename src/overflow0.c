#include <stdio.h>
 
/*
gcc -g -fno-stack-protector overflow0.c -o overflow0
*/
 
 
 
int main(int argc, char** argv)
{
   char not_overflow;
   int privileges=0;
   char buffer[64];

   printf("Enter some text: \n");

   not_overflow = 'Y';
   gets(buffer);

   if (not_overflow == 'Y') {
      printf("Can't Overflow Me\nThis is the content of the buffer:\n%s\n", buffer);
   }
   else
   {
      privileges = 1;
   }

   if(privileges == 1)
   {
      printf("Your secret password is stefano123");
   }

   return 0;
}
