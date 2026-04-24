// Function: FUN_8025ca1c
// Entry: 8025ca1c
// Size: 796 bytes

void FUN_8025ca1c(double param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  int local_a0 [2];
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  
  dVar11 = (double)FLOAT_803e7748;
  dVar10 = (double)(float)((double)FLOAT_803e7730 - param_1);
  FUN_802571d4(0xd,local_a0);
  FUN_80257388(&DAT_803aea38);
  FUN_80257e00(3,&DAT_803aeb10);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(10,1);
  FUN_80257444(3,9,1,4,0);
  FUN_80257444(3,10,0,4,0);
  if (local_a0[0] != 0) {
    FUN_80256978(0xd,1);
    FUN_80257444(3,0xd,1,4,0);
  }
  param_3 = param_3 & 0xff;
  param_2 = param_2 & 0xff;
  dVar13 = DOUBLE_803e7738;
  dVar14 = DOUBLE_803e7740;
  for (iVar5 = 0; iVar5 < (int)param_2; iVar5 = iVar5 + 1) {
    FUN_8025889c(0x98,3,(param_3 + 1) * 2);
    for (uVar4 = 0; (int)uVar4 <= (int)param_3; uVar4 = uVar4 + 1) {
      uVar2 = uVar4 - ((int)uVar4 / (int)param_3) * param_3 ^ 0x80000000;
      iVar3 = 1;
      do {
        uVar1 = iVar5 + iVar3;
        local_88 = 0x43300000;
        local_90 = 0x43300000;
        dVar12 = (double)((float)((double)(float)((double)CONCAT44(0x43300000,uVar2) - dVar13) *
                                 dVar11) / (float)((double)CONCAT44(0x43300000,param_3) - dVar14));
        uStack124 = uVar1 - ((int)uVar1 / (int)param_2) * param_2 ^ 0x80000000;
        local_80 = 0x43300000;
        dVar7 = (double)(float)((double)CONCAT44(0x43300000,uStack124) - dVar13);
        uStack140 = param_3;
        uStack132 = uVar2;
        dVar6 = (double)FUN_80294850(dVar12);
        local_98 = 0x43300000;
        dVar9 = (double)((float)(dVar7 * dVar11) /
                        (float)((double)CONCAT44(0x43300000,param_2) - dVar14));
        uStack148 = param_2;
        dVar7 = (double)FUN_80294850(dVar9);
        dVar8 = (double)(float)((double)(float)(dVar10 - (double)(float)(param_1 * dVar7)) * dVar6);
        dVar6 = (double)FUN_802949e4(dVar12);
        dVar7 = (double)FUN_80294850(dVar9);
        dVar7 = (double)(float)((double)(float)(dVar10 - (double)(float)(param_1 * dVar7)) * dVar6);
        dVar6 = (double)FUN_802949e4(dVar9);
        write_volatile_4(0xcc008000,(float)dVar8);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)(param_1 * dVar6));
        dVar6 = (double)FUN_80294850(dVar9);
        dVar7 = (double)FUN_80294850(dVar12);
        dVar8 = (double)(float)(-dVar7 * dVar6);
        dVar6 = (double)FUN_80294850(dVar9);
        dVar7 = (double)FUN_802949e4(dVar12);
        dVar7 = (double)(float)(-dVar7 * dVar6);
        dVar6 = (double)FUN_802949e4(dVar9);
        write_volatile_4(0xcc008000,(float)dVar8);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar6);
        if (local_a0[0] != 0) {
          uStack148 = uVar1 ^ 0x80000000;
          local_98 = 0x43300000;
          local_90 = 0x43300000;
          local_88 = 0x43300000;
          local_80 = 0x43300000;
          write_volatile_4(0xcc008000,
                           (float)((double)CONCAT44(0x43300000,uStack148) - dVar13) /
                           (float)((double)CONCAT44(0x43300000,param_2) - dVar14));
          write_volatile_4(0xcc008000,
                           (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - dVar13) /
                           (float)((double)CONCAT44(0x43300000,param_3) - dVar14));
          uStack140 = param_2;
          uStack132 = uVar4 ^ 0x80000000;
          uStack124 = param_3;
        }
        iVar3 = iVar3 + -1;
      } while (-1 < iVar3);
    }
  }
  FUN_80256cd8(&DAT_803aea38);
  FUN_802577a0(3,&DAT_803aeb10);
  return;
}

