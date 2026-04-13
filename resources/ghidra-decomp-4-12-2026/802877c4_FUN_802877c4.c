// Function: FUN_802877c4
// Entry: 802877c4
// Size: 232 bytes

int FUN_802877c4(int param_1,undefined *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined *puVar4;
  undefined auStack_28 [20];
  
  puVar4 = param_2;
  if (DAT_803d7578 == 0) {
    puVar4 = auStack_28;
  }
  iVar3 = 0;
  uVar1 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
  uVar2 = 8;
  if (uVar1 < 8) {
    iVar3 = 0x302;
    uVar2 = uVar1;
  }
  FUN_80003514((int)puVar4,param_1 + *(int *)(param_1 + 0xc) + 0x10,uVar2);
  *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar2;
  if ((DAT_803d7578 == 0) && (iVar3 == 0)) {
    *param_2 = puVar4[7];
    param_2[1] = puVar4[6];
    param_2[2] = puVar4[5];
    param_2[3] = puVar4[4];
    param_2[4] = puVar4[3];
    param_2[5] = puVar4[2];
    param_2[6] = puVar4[1];
    param_2[7] = *puVar4;
  }
  return iVar3;
}

