// Function: FUN_80291f08
// Entry: 80291f08
// Size: 68 bytes

void FUN_80291f08(int param_1,int param_2,int param_3)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  
  pcVar2 = (char *)(param_2 + -1);
  pcVar4 = (char *)(param_1 + -1);
  iVar3 = param_3 + 1;
  do {
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return;
    }
    pcVar2 = pcVar2 + 1;
    cVar1 = *pcVar2;
    pcVar4 = pcVar4 + 1;
    *pcVar4 = cVar1;
  } while (cVar1 != '\0');
  while (iVar3 = iVar3 + -1, iVar3 != 0) {
    pcVar4 = pcVar4 + 1;
    *pcVar4 = '\0';
  }
  return;
}

