#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

char flag[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
char password[100];

int main(void)
{
  FILE* fp = fopen("./password", "r");
  fgets(password, 100, fp);

  for (int i = 0; i < strlen(password); i++)
  {
		flag[i] = password[i] ^ key[i];
  }

  (void)printf("%s\n", flag);

  return 0;
}
