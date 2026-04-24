// Function: FUN_8025d180
// Entry: 8025d180
// Size: 796 bytes

void FUN_8025d180(double param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  uint local_a0 [2];
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  
  dVar13 = (double)FLOAT_803e83e0;
  dVar12 = (double)(float)((double)FLOAT_803e83c8 - param_1);
  FUN_80257938(0xd,local_a0);
  FUN_80257aec(-0x7fc50968);
  FUN_80258564(3,(int *)&DAT_803af770);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(10,1);
  FUN_80257ba8(3,9,1,4,0);
  FUN_80257ba8(3,10,0,4,0);
  if (local_a0[0] != 0) {
    FUN_802570dc(0xd,1);
    FUN_80257ba8(3,0xd,1,4,0);
  }
  uVar1 = param_3 & 0xff;
  uVar2 = param_2 & 0xff;
  dVar15 = DOUBLE_803e83d0;
  dVar16 = DOUBLE_803e83d8;
  for (iVar7 = 0; iVar7 < (int)uVar2; iVar7 = iVar7 + 1) {
    FUN_80259000(0x98,3,(uVar1 + 1) * 2);
    for (uVar6 = 0; (int)uVar6 <= (int)uVar1; uVar6 = uVar6 + 1) {
      uVar4 = uVar6 - ((int)uVar6 / (int)uVar1) * uVar1 ^ 0x80000000;
      iVar5 = 1;
      do {
        uVar3 = iVar7 + iVar5;
        local_88 = 0x43300000;
        local_90 = 0x43300000;
        dVar14 = (double)((float)((double)(float)((double)CONCAT44(0x43300000,uVar4) - dVar15) *
                                 dVar13) / (float)((double)CONCAT44(0x43300000,uVar1) - dVar16));
        uStack_7c = uVar3 - ((int)uVar3 / (int)uVar2) * uVar2 ^ 0x80000000;
        local_80 = 0x43300000;
        dVar9 = (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - dVar15);
        uStack_8c = uVar1;
        uStack_84 = uVar4;
        dVar8 = FUN_80294fb0(dVar14);
        local_98 = 0x43300000;
        dVar11 = (double)((float)(dVar9 * dVar13) /
                         (float)((double)CONCAT44(0x43300000,uVar2) - dVar16));
        uStack_94 = uVar2;
        dVar9 = FUN_80294fb0(dVar11);
        dVar10 = (double)(float)((double)(float)(dVar12 - (double)(float)(param_1 * dVar9)) * dVar8)
        ;
        dVar8 = FUN_80295144(dVar14);
        dVar9 = FUN_80294fb0(dVar11);
        dVar9 = (double)(float)((double)(float)(dVar12 - (double)(float)(param_1 * dVar9)) * dVar8);
        dVar8 = FUN_80295144(dVar11);
        DAT_cc008000 = (float)dVar10;
        DAT_cc008000 = (float)dVar9;
        DAT_cc008000 = (float)(param_1 * dVar8);
        dVar8 = FUN_80294fb0(dVar11);
        dVar9 = FUN_80294fb0(dVar14);
        dVar10 = (double)(float)(-dVar9 * dVar8);
        dVar8 = FUN_80294fb0(dVar11);
        dVar9 = FUN_80295144(dVar14);
        dVar9 = (double)(float)(-dVar9 * dVar8);
        dVar8 = FUN_80295144(dVar11);
        DAT_cc008000 = (float)dVar10;
        DAT_cc008000 = (float)dVar9;
        DAT_cc008000 = (float)dVar8;
        if (local_a0[0] != 0) {
          uStack_94 = uVar3 ^ 0x80000000;
          local_98 = 0x43300000;
          local_90 = 0x43300000;
          local_88 = 0x43300000;
          local_80 = 0x43300000;
          DAT_cc008000 = (float)((double)CONCAT44(0x43300000,uStack_94) - dVar15) /
                         (float)((double)CONCAT44(0x43300000,uVar2) - dVar16);
          DAT_cc008000 = (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - dVar15) /
                         (float)((double)CONCAT44(0x43300000,uVar1) - dVar16);
          uStack_8c = uVar2;
          uStack_84 = uVar6 ^ 0x80000000;
          uStack_7c = uVar1;
        }
        iVar5 = iVar5 + -1;
      } while (-1 < iVar5);
    }
  }
  FUN_8025743c((int *)&DAT_803af698);
  FUN_80257f04(3,(int *)&DAT_803af770);
  return;
}

