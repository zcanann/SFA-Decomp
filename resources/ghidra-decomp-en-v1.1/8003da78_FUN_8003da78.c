// Function: FUN_8003da78
// Entry: 8003da78
// Size: 720 bytes

void FUN_8003da78(ushort *param_1,int param_2)

{
  float fVar1;
  float *pfVar2;
  uint uVar3;
  ushort *puVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  ushort *puVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  double dVar13;
  undefined2 local_f8;
  undefined2 local_f6;
  undefined2 local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float afStack_e0 [12];
  float afStack_b0 [3];
  float local_a4;
  float local_94;
  float local_84;
  float afStack_70 [16];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar11 = *(int **)(param_2 + 0x58);
  pfVar2 = (float *)FUN_8000f56c();
  FUN_8002b554(param_1,afStack_70,'\0');
  FUN_80247618(pfVar2,afStack_70,afStack_b0);
  FUN_8025d80c(afStack_b0,(uint)DAT_802cbaa8);
  FUN_8025d888((uint)DAT_802cbaa8);
  dVar13 = (double)(float)((double)FLOAT_803df69c / (double)*(float *)(param_1 + 4));
  FUN_80247a7c(dVar13,dVar13,(double)FLOAT_803df69c,afStack_e0);
  local_a4 = FLOAT_803df684;
  local_94 = FLOAT_803df684;
  local_84 = FLOAT_803df684;
  FUN_80247618(afStack_b0,afStack_e0,afStack_b0);
  FUN_8025d8c4(afStack_b0,0x1e,0);
  FUN_80072f78(param_1,param_2,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(10,1);
  FUN_802570dc(0xd,1);
  iVar10 = piVar11[1];
  iVar9 = piVar11[2];
  FUN_80259000(0x90,7,(uint)*(ushort *)(piVar11 + 3) * 3 & 0xffff);
  iVar5 = 0;
  for (iVar7 = 0; iVar7 < (int)(uint)*(ushort *)(piVar11 + 3); iVar7 = iVar7 + 1) {
    puVar8 = (ushort *)(*piVar11 + iVar5);
    iVar12 = 3;
    puVar4 = puVar8;
    do {
      puVar6 = (undefined2 *)(iVar10 + (uint)*puVar4 * 6);
      DAT_cc008000._0_2_ = *puVar6;
      DAT_cc008000._0_2_ = puVar6[1];
      DAT_cc008000._0_2_ = puVar6[2];
      DAT_cc008000._0_1_ = *(undefined *)(puVar8 + 3);
      DAT_cc008000._0_1_ = *(undefined *)((int)puVar8 + 7);
      DAT_cc008000._0_1_ = *(undefined *)(puVar8 + 4);
      puVar6 = (undefined2 *)(iVar9 + (uint)*puVar4 * 4);
      DAT_cc008000._0_2_ = *puVar6;
      DAT_cc008000._0_2_ = puVar6[1];
      puVar4 = puVar4 + 1;
      iVar12 = iVar12 + -1;
    } while (iVar12 != 0);
    iVar5 = iVar5 + 10;
  }
  FUN_8025d888(0);
  uVar3 = FUN_80022264(0,5);
  if (uVar3 == 0) {
    uVar3 = FUN_80022264(0,(int)*(short *)((int)piVar11 + 0xe) - 1);
    fVar1 = *(float *)(param_1 + 4);
    uStack_2c = (int)*(short *)(iVar10 + uVar3 * 6) >> 8 ^ 0x80000000;
    local_30 = 0x43300000;
    local_ec = fVar1 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df6c0) +
               *(float *)(param_1 + 6);
    iVar10 = iVar10 + uVar3 * 6;
    uStack_24 = (int)*(short *)(iVar10 + 2) >> 8 ^ 0x80000000;
    local_28 = 0x43300000;
    local_e8 = fVar1 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df6c0) +
               *(float *)(param_1 + 8);
    uStack_1c = (int)*(short *)(iVar10 + 4) >> 8 ^ 0x80000000;
    local_20 = 0x43300000;
    local_e4 = fVar1 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df6c0) +
               *(float *)(param_1 + 10);
    local_f0 = FLOAT_803df69c;
    local_f8 = 0;
    local_f4 = 0;
    local_f6 = 0;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fd,&local_f8,0x200001,0xffffffff,0);
  }
  return;
}

