// Function: FUN_8028f9d4
// Entry: 8028f9d4
// Size: 44 bytes

char * FUN_8028f9d4(int param_1,char param_2,int param_3)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = (char *)(param_1 + param_3);
  iVar2 = param_3 + 1;
  do {
    iVar2 = iVar2 + -1;
    if (iVar2 == 0) {
      return (char *)0x0;
    }
    pcVar1 = pcVar1 + -1;
  } while (*pcVar1 != param_2);
  return pcVar1;
}

