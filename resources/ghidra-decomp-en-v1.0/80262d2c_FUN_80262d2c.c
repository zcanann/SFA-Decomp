// Function: FUN_80262d2c
// Entry: 80262d2c
// Size: 104 bytes

undefined4 FUN_80262d2c(int param_1,char *param_2)

{
  char cVar1;
  char cVar2;
  char *pcVar3;
  int iVar4;
  
  pcVar3 = (char *)(param_1 + 8);
  iVar4 = 0x20;
  do {
    iVar4 = iVar4 + -1;
    if (iVar4 < 0) {
      if (*param_2 == '\0') {
        return 1;
      }
      return 0;
    }
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
    cVar2 = *param_2;
    param_2 = param_2 + 1;
    if (cVar1 != cVar2) {
      return 0;
    }
  } while (cVar2 != '\0');
  return 1;
}

