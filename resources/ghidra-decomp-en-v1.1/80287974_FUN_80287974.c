// Function: FUN_80287974
// Entry: 80287974
// Size: 184 bytes

int FUN_80287974(int param_1,undefined *param_2)

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
  uVar3 = 2;
  if (uVar1 < 2) {
    iVar4 = 0x302;
    uVar3 = uVar1;
  }
  FUN_80003514((int)puVar2,param_1 + *(int *)(param_1 + 0xc) + 0x10,uVar3);
  *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar3;
  if ((DAT_803d7578 == 0) && (iVar4 == 0)) {
    *param_2 = puVar2[1];
    param_2[1] = *puVar2;
  }
  return iVar4;
}

