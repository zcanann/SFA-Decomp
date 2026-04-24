// Function: FUN_8012c9e8
// Entry: 8012c9e8
// Size: 848 bytes

void FUN_8012c9e8(undefined4 param_1,undefined4 param_2,short param_3,short param_4,uint param_5,
                 uint param_6)

{
  short sVar1;
  short extraout_r4;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  
  sVar1 = FUN_80286818();
  uVar2 = (uint)sVar1;
  uVar6 = uVar2 - 5;
  uVar3 = (uint)extraout_r4;
  uVar7 = uVar3 - 5;
  FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8),
               DAT_803a9638,param_5,0x100);
  iVar4 = (int)param_3;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8),
               DAT_803a9644,param_5,0x100,iVar4,5,0);
  iVar5 = (int)param_4;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e2af8),
               DAT_803a963c,param_5,0x100,5,iVar5,0);
  if ((param_6 & 0xff) != 0) {
    FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
                 (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9640,param_5,0x100,iVar4,iVar5,0);
  }
  uVar3 = uVar3 + (int)param_4;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) -
                              DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e2af8),
               DAT_803a9644,param_5,0x100,iVar4,5,2);
  uVar2 = uVar2 + (int)param_3;
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,(int)extraout_r4 ^ 0x80000000) -
                              DOUBLE_803e2af8),DAT_803a963c,param_5,0x100,5,iVar5,1);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e2af8),
               DAT_803a9638,param_5,0x100,5,5,3);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8),
               DAT_803a9638,param_5,0x100,5,5,1);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2af8),
               (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e2af8),
               DAT_803a9638,param_5,0x100,5,5,2);
  FUN_80286864();
  return;
}

