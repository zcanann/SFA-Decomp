// Function: FUN_8028f274
// Entry: 8028f274
// Size: 44 bytes

char * FUN_8028f274(int param_1,char param_2,int param_3)

{
  char *pcVar1;
  
  pcVar1 = (char *)(param_1 + param_3);
  param_3 = param_3 + 1;
  do {
    param_3 = param_3 + -1;
    if (param_3 == 0) {
      return (char *)0x0;
    }
    pcVar1 = pcVar1 + -1;
  } while (*pcVar1 != param_2);
  return pcVar1;
}

