// Function: FUN_80287148
// Entry: 80287148
// Size: 200 bytes

int FUN_80287148(int param_1,undefined *param_2)

{
  uint uVar1;
  undefined *puVar2;
  uint uVar3;
  int iVar4;
  undefined auStack40 [20];
  
  puVar2 = param_2;
  if (DAT_803d6918 == 0) {
    puVar2 = auStack40;
  }
  iVar4 = 0;
  uVar1 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
  uVar3 = 4;
  if (uVar1 < 4) {
    iVar4 = 0x302;
    uVar3 = uVar1;
  }
  FUN_80003514(puVar2,param_1 + *(int *)(param_1 + 0xc) + 0x10,uVar3);
  *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar3;
  if ((DAT_803d6918 == 0) && (iVar4 == 0)) {
    *param_2 = puVar2[3];
    param_2[1] = puVar2[2];
    param_2[2] = puVar2[1];
    param_2[3] = *puVar2;
  }
  return iVar4;
}

