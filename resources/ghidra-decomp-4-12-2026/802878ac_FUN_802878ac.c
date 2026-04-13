// Function: FUN_802878ac
// Entry: 802878ac
// Size: 200 bytes

int FUN_802878ac(int param_1,undefined *param_2)

{
  uint uVar1;
  undefined *puVar2;
  uint uVar3;
  int iVar4;
  undefined auStack_28 [20];
  
  puVar2 = param_2;
  if (DAT_803d7578 == 0) {
    puVar2 = auStack_28;
  }
  iVar4 = 0;
  uVar1 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
  uVar3 = 4;
  if (uVar1 < 4) {
    iVar4 = 0x302;
    uVar3 = uVar1;
  }
  FUN_80003514((int)puVar2,param_1 + *(int *)(param_1 + 0xc) + 0x10,uVar3);
  *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar3;
  if ((DAT_803d7578 == 0) && (iVar4 == 0)) {
    *param_2 = puVar2[3];
    param_2[1] = puVar2[2];
    param_2[2] = puVar2[1];
    param_2[3] = *puVar2;
  }
  return iVar4;
}

