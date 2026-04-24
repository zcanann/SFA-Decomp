// Function: FUN_802917a8
// Entry: 802917a8
// Size: 68 bytes

void FUN_802917a8(int param_1,int param_2,int param_3)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  
  pcVar2 = (char *)(param_2 + -1);
  pcVar3 = (char *)(param_1 + -1);
  param_3 = param_3 + 1;
  do {
    param_3 = param_3 + -1;
    if (param_3 == 0) {
      return;
    }
    pcVar2 = pcVar2 + 1;
    cVar1 = *pcVar2;
    pcVar3 = pcVar3 + 1;
    *pcVar3 = cVar1;
  } while (cVar1 != '\0');
  while (param_3 = param_3 + -1, param_3 != 0) {
    pcVar3 = pcVar3 + 1;
    *pcVar3 = '\0';
  }
  return;
}

