// Function: FUN_80036708
// Entry: 80036708
// Size: 104 bytes

void FUN_80036708(int param_1,int param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x58);
  if (iVar4 == 0) {
    return;
  }
  iVar2 = (int)*(char *)(iVar4 + 0x10f);
  if (2 < iVar2) {
    return;
  }
  iVar3 = 0;
  if (0 < iVar2) {
    do {
      if (*(int *)(iVar4 + iVar3 + 0x100) == param_2) {
        return;
      }
      iVar3 = iVar3 + 4;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  iVar2 = *(int *)(param_1 + 0x58);
  cVar1 = *(char *)(iVar4 + 0x10f);
  *(char *)(iVar4 + 0x10f) = cVar1 + '\x01';
  *(int *)(iVar2 + cVar1 * 4 + 0x100) = param_2;
  return;
}

