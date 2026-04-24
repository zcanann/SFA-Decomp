// Function: FUN_80079fe0
// Entry: 80079fe0
// Size: 2232 bytes

/* WARNING: Removing unreachable block (ram,0x8007a878) */
/* WARNING: Removing unreachable block (ram,0x8007a870) */
/* WARNING: Removing unreachable block (ram,0x8007a868) */
/* WARNING: Removing unreachable block (ram,0x8007a860) */
/* WARNING: Removing unreachable block (ram,0x8007a858) */
/* WARNING: Removing unreachable block (ram,0x8007a850) */
/* WARNING: Removing unreachable block (ram,0x8007a018) */
/* WARNING: Removing unreachable block (ram,0x8007a010) */
/* WARNING: Removing unreachable block (ram,0x8007a008) */
/* WARNING: Removing unreachable block (ram,0x8007a000) */
/* WARNING: Removing unreachable block (ram,0x80079ff8) */
/* WARNING: Removing unreachable block (ram,0x80079ff0) */

void FUN_80079fe0(double param_1,double param_2,double param_3,undefined param_4,undefined4 param_5,
                 undefined param_6,undefined param_7)

{
  ushort uVar2;
  int iVar1;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined4 local_f8;
  undefined4 local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  int local_e0;
  int local_dc;
  float afStack_d8 [12];
  float afStack_a8 [12];
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  
  local_e8 = CONCAT31(local_e8._0_3_,param_6);
  local_ec = CONCAT31(local_ec._0_3_,param_7);
  uVar2 = FUN_8000fab0();
  uStack_74 = (uint)uVar2;
  local_78 = 0x43300000;
  dVar5 = (double)(((float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803dfb80) -
                   FLOAT_803dfbd4) / FLOAT_803dfbd8);
  uVar2 = FUN_8000fa90();
  uStack_6c = (uint)uVar2;
  local_70 = 0x43300000;
  dVar3 = (double)(((float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803dfb80) -
                   FLOAT_803dfbd4) / FLOAT_803dfbd8);
  iVar1 = FUN_80020800();
  if (iVar1 == 0) {
    dVar4 = (double)FUN_802928f4();
    dVar4 = FUN_80021434((double)(float)(dVar4 - (double)FLOAT_803ddc8c),(double)FLOAT_803dfbdc,
                         (double)FLOAT_803dc074);
    FLOAT_803ddc8c = (float)((double)FLOAT_803ddc8c + dVar4);
  }
  dVar4 = (double)FLOAT_803ddc8c;
  local_e4 = CONCAT31(local_e4._0_3_,param_4);
  FUN_8006c754(&local_dc);
  FUN_8004c460(local_dc,0);
  FUN_8006c674(&local_e0);
  FUN_8004c460(local_e0,1);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_80247a7c((double)(float)((double)FLOAT_803dfbe0 * param_2),
               (double)(float)((double)FLOAT_803dfbe0 * param_2),(double)FLOAT_803dfb5c,afStack_a8);
  FUN_80247a48((double)(float)(dVar5 * param_3),(double)(float)(dVar3 * param_3 + param_1),
               (double)FLOAT_803dfb5c,afStack_d8);
  FUN_80247618(afStack_d8,afStack_a8,afStack_a8);
  FUN_8024782c(dVar4,afStack_d8,0x7a);
  FUN_80247618(afStack_a8,afStack_d8,afStack_a8);
  FUN_80247a48((double)FLOAT_803dfb74,(double)FLOAT_803dfb74,(double)FLOAT_803dfb5c,afStack_d8);
  FUN_80247618(afStack_a8,afStack_d8,afStack_a8);
  FUN_8025d8c4(afStack_a8,0x1e,1);
  FUN_80258674(1,1,4,0x1e,0,0x7d);
  FUN_80247a7c((double)(float)((double)FLOAT_803dfbe4 * param_2),
               (double)(float)((double)FLOAT_803dfbe4 * param_2),(double)FLOAT_803dfb5c,afStack_a8);
  FUN_80247a48((double)(float)((double)(float)((double)FLOAT_803dfb60 * dVar5) * param_3),
               (double)(float)((double)FLOAT_803dfbe8 * param_1 +
                              (double)(float)((double)(float)((double)FLOAT_803dfb60 * dVar3) *
                                             param_3)),(double)FLOAT_803dfb5c,afStack_d8);
  FUN_80247618(afStack_d8,afStack_a8,afStack_a8);
  FUN_8024782c((double)(float)((double)FLOAT_803dfb78 * dVar4),afStack_d8,0x7a);
  FUN_80247618(afStack_a8,afStack_d8,afStack_a8);
  FUN_80247a48((double)FLOAT_803dfb74,(double)FLOAT_803dfb74,(double)FLOAT_803dfb5c,afStack_d8);
  FUN_80247618(afStack_a8,afStack_d8,afStack_a8);
  FUN_8025d8c4(afStack_a8,0x21,1);
  FUN_80258674(2,1,4,0x21,0,0x7d);
  local_f0 = local_e8;
  FUN_8025c510(0,(byte *)&local_f0);
  FUN_8025c5f0(0,0x1c);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  FUN_8025c224(0,6,7,7,4);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,1,0,2,1,0);
  FUN_8025be80(1);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,8,0xf,0xf,0xf);
  FUN_8025c224(1,7,0,4,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,1,1,0);
  local_f4 = local_ec;
  FUN_8025c510(1,(byte *)&local_f4);
  FUN_8025c5f0(2,0x1d);
  FUN_8025be80(2);
  FUN_8025c828(2,0,0,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0xf);
  FUN_8025c224(2,6,7,7,4);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,1);
  FUN_8025c368(2,1,0,2,1,1);
  FUN_8025be80(3);
  FUN_8025c828(3,2,1,0xff);
  FUN_8025c1a4(3,8,0xf,0xf,0xf);
  FUN_8025c224(3,7,1,4,7);
  FUN_8025c65c(3,0,0);
  FUN_8025c2a8(3,0,0,0,1,1);
  FUN_8025c368(3,0,0,2,1,1);
  FUN_8025c5f0(4,0);
  FUN_8025be80(4);
  FUN_8025c828(4,0xff,0xff,0xff);
  FUN_8025c1a4(4,0,2,3,0xf);
  FUN_8025c224(4,0,6,1,7);
  FUN_8025c65c(4,0,0);
  FUN_8025c2a8(4,0,0,0,1,0);
  FUN_8025c368(4,0,0,0,1,0);
  local_f8 = local_e4;
  FUN_8025c510(2,(byte *)&local_f8);
  FUN_8025c5f0(5,0x1e);
  FUN_8025be80(5);
  FUN_8025c828(5,0xff,0xff,0xff);
  FUN_8025c1a4(5,0xf,0xf,0xf,0);
  FUN_8025c224(5,7,0,6,7);
  FUN_8025c65c(5,0,0);
  FUN_8025c2a8(5,0,0,0,1,0);
  FUN_8025c368(5,0,0,0,1,0);
  FUN_80258944(3);
  FUN_8025ca04(6);
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80257b5c();
  FUN_8025d888(0x3c);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  FUN_8025cce8(1,4,5,5);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 1)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,1,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 1;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  FUN_80259000(0x80,0,4);
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x80;
  FUN_8000fb20();
  FUN_8025d888(0);
  return;
}

