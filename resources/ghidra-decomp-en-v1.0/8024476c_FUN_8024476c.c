// Function: FUN_8024476c
// Entry: 8024476c
// Size: 132 bytes

void FUN_8024476c(int param_1)

{
  int iVar1;
  int iVar2;
  
  for (iVar2 = DAT_803dde60; (iVar2 != 0 && (*(uint *)(iVar2 + 4) <= *(uint *)(param_1 + 4)));
      iVar2 = *(int *)(iVar2 + 8)) {
  }
  if (iVar2 != 0) {
    *(int *)(param_1 + 8) = iVar2;
    iVar1 = *(int *)(iVar2 + 0xc);
    *(int *)(iVar2 + 0xc) = param_1;
    *(int *)(param_1 + 0xc) = iVar1;
    if (iVar1 != 0) {
      *(int *)(iVar1 + 8) = param_1;
      return;
    }
    DAT_803dde60 = param_1;
    return;
  }
  iVar2 = param_1;
  if (iRam803dde64 != 0) {
    *(int *)(iRam803dde64 + 8) = param_1;
    iVar2 = DAT_803dde60;
  }
  DAT_803dde60 = iVar2;
  *(int *)(param_1 + 0xc) = iRam803dde64;
  *(undefined4 *)(param_1 + 8) = 0;
  iRam803dde64 = param_1;
  return;
}

