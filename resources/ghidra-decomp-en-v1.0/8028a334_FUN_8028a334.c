// Function: FUN_8028a334
// Entry: 8028a334
// Size: 228 bytes

int FUN_8028a334(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined auStack40 [28];
  
  DAT_803d82f0 = 0;
  FUN_802876f8(param_1,1);
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = 0x80;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 < 0x880) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
    *(undefined *)(param_1 + uVar1 + 0x10) = 0;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  iVar3 = 3;
  do {
    iVar2 = FUN_80286cfc(param_1);
    iVar3 = iVar3 + -1;
    if (iVar2 == 0) break;
  } while (0 < iVar3);
  if (iVar2 == 0) {
    FUN_80286978(auStack40,1);
    FUN_80286990(auStack40);
  }
  return iVar2;
}

