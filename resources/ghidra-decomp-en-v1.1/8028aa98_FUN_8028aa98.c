// Function: FUN_8028aa98
// Entry: 8028aa98
// Size: 228 bytes

int FUN_8028aa98(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined auStack_28 [28];
  
  DAT_803d8f50 = 0;
  FUN_80287e5c(param_1,'\x01');
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
    iVar2 = FUN_80287460(param_1);
    iVar3 = iVar3 + -1;
    if (iVar2 == 0) break;
  } while (0 < iVar3);
  if (iVar2 == 0) {
    FUN_802870dc(auStack_28,1);
    FUN_802870f4((int)auStack_28);
  }
  return iVar2;
}

