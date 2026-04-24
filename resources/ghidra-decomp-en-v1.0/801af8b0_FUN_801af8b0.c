// Function: FUN_801af8b0
// Entry: 801af8b0
// Size: 196 bytes

void FUN_801af8b0(int param_1)

{
  int iVar1;
  int iVar2;
  char cVar3;
  char *pcVar4;
  
  pcVar4 = *(char **)(param_1 + 0xb8);
  iVar1 = FUN_8002b9ec();
  if (iVar1 != 0) {
    if (*pcVar4 != *(char *)(param_1 + 0xac)) {
      iVar2 = FUN_8005afac((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x14));
      if (*(char *)(param_1 + 0xac) != iVar2) {
        return;
      }
      FUN_801af6dc(param_1);
    }
    iVar2 = FUN_8005afac((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x14));
    if (*(char *)(param_1 + 0xac) == iVar2) {
      FUN_801af568(param_1);
    }
    cVar3 = FUN_8005afac((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x14));
    *pcVar4 = cVar3;
  }
  return;
}

