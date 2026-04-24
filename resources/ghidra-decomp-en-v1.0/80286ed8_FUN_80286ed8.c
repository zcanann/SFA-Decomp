// Function: FUN_80286ed8
// Entry: 80286ed8
// Size: 240 bytes

void FUN_80286ed8(int param_1,undefined *param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  int iVar5;
  undefined auStack40 [8];
  
  iVar2 = 0;
  for (iVar5 = 0; (iVar2 == 0 && (iVar5 < param_3)); iVar5 = iVar5 + 1) {
    puVar4 = param_2;
    if (DAT_803d6918 == 0) {
      puVar4 = auStack40;
    }
    iVar2 = 0;
    uVar1 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
    uVar3 = 4;
    if (uVar1 < 4) {
      iVar2 = 0x302;
      uVar3 = uVar1;
    }
    FUN_80003514(puVar4,param_1 + *(int *)(param_1 + 0xc) + 0x10,uVar3);
    *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar3;
    if ((DAT_803d6918 == 0) && (iVar2 == 0)) {
      *param_2 = puVar4[3];
      param_2[1] = puVar4[2];
      param_2[2] = puVar4[1];
      param_2[3] = *puVar4;
    }
    param_2 = param_2 + 4;
  }
  return;
}

