// Function: FUN_80244e64
// Entry: 80244e64
// Size: 132 bytes

void FUN_80244e64(int param_1)

{
  int iVar1;
  int iVar2;
  
  for (iVar2 = DAT_803deae0; (iVar2 != 0 && (*(uint *)(iVar2 + 4) <= *(uint *)(param_1 + 4)));
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
    DAT_803deae0 = param_1;
    return;
  }
  iVar2 = param_1;
  if (iRam803deae4 != 0) {
    *(int *)(iRam803deae4 + 8) = param_1;
    iVar2 = DAT_803deae0;
  }
  DAT_803deae0 = iVar2;
  *(int *)(param_1 + 0xc) = iRam803deae4;
  *(undefined4 *)(param_1 + 8) = 0;
  iRam803deae4 = param_1;
  return;
}

