// Function: FUN_80076144
// Entry: 80076144
// Size: 1352 bytes

/* WARNING: Removing unreachable block (ram,0x8007666c) */
/* WARNING: Removing unreachable block (ram,0x80076664) */
/* WARNING: Removing unreachable block (ram,0x8007665c) */
/* WARNING: Removing unreachable block (ram,0x80076654) */
/* WARNING: Removing unreachable block (ram,0x8007664c) */
/* WARNING: Removing unreachable block (ram,0x80076644) */
/* WARNING: Removing unreachable block (ram,0x8007617c) */
/* WARNING: Removing unreachable block (ram,0x80076174) */
/* WARNING: Removing unreachable block (ram,0x8007616c) */
/* WARNING: Removing unreachable block (ram,0x80076164) */
/* WARNING: Removing unreachable block (ram,0x8007615c) */
/* WARNING: Removing unreachable block (ram,0x80076154) */

void FUN_80076144(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,int param_8,int param_9)

{
  uint uVar1;
  undefined2 uVar2;
  undefined2 uVar3;
  undefined2 uVar4;
  int iVar5;
  double extraout_f1;
  double in_f26;
  double dVar6;
  double in_f27;
  double dVar7;
  double in_f28;
  double dVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  int iStack_10c;
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  int iStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  int iStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  int iStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  longlong local_d0;
  longlong local_c8;
  undefined4 local_c0;
  uint uStack_bc;
  longlong local_b8;
  longlong local_b0;
  longlong local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  longlong local_98;
  longlong local_90;
  longlong local_88;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar12 = FUN_80286838();
  iVar5 = (int)((ulonglong)uVar12 >> 0x20);
  local_114 = CONCAT31(0xffffff,(char)(((uint)uVar12 & 0xff) * (uint)DAT_803dc2d9 >> 8));
  dVar6 = extraout_f1;
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  local_118 = local_114;
  FUN_8025c510(0,(byte *)&local_118);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,8);
  FUN_8025c224(0,7,4,6,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  if (*(int *)(iVar5 + 0x50) == 0) {
    FUN_8025ca04(1);
  }
  else {
    FUN_8025c5f0(1,0x1c);
    FUN_8025c828(1,0,1,0xff);
    FUN_8025be80(1);
    FUN_8025c1a4(1,0xf,0xf,0xf,0);
    FUN_8025c224(1,7,4,6,7);
    FUN_8025c65c(1,0,0);
    FUN_8025c2a8(1,0,0,0,1,0);
    FUN_8025c368(1,0,0,0,1,0);
    FUN_8025ca04(2);
  }
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(1);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8004c3e0(iVar5,0);
  FUN_80259288(0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  if ((((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 7)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(0,7,0);
    DAT_803ddc98 = '\0';
    DAT_803ddc94 = 7;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  FUN_8025cce8(1,4,5,5);
  uVar1 = param_6 * 4 * (param_5 & 0xffff) >> 8;
  dVar7 = (double)(float)((double)FLOAT_803dfbac * dVar6);
  dVar8 = (double)(float)((double)FLOAT_803dfbac * param_2);
  local_110 = 0x43300000;
  uStack_104 = (uint)*(ushort *)(iVar5 + 10);
  local_108 = 0x43300000;
  dVar10 = (double)((float)((double)CONCAT44(0x43300000,param_8) - DOUBLE_803dfb80) /
                   (float)((double)CONCAT44(0x43300000,uStack_104) - DOUBLE_803dfb80));
  local_100 = 0x43300000;
  uStack_f4 = (uint)*(ushort *)(iVar5 + 0xc);
  local_f8 = 0x43300000;
  dVar9 = (double)((float)((double)CONCAT44(0x43300000,param_9) - DOUBLE_803dfb80) /
                  (float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803dfb80));
  iStack_ec = param_6 + param_8;
  local_f0 = 0x43300000;
  local_e8 = 0x43300000;
  dVar11 = (double)((float)((double)CONCAT44(0x43300000,iStack_ec) - DOUBLE_803dfb80) /
                   (float)((double)CONCAT44(0x43300000,uStack_104) - DOUBLE_803dfb80));
  iStack_dc = param_7 + param_9;
  local_e0 = 0x43300000;
  local_d8 = 0x43300000;
  dVar6 = (double)((float)((double)CONCAT44(0x43300000,iStack_dc) - DOUBLE_803dfb80) /
                  (float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803dfb80));
  iStack_10c = param_8;
  iStack_fc = param_9;
  uStack_e4 = uStack_104;
  uStack_d4 = uStack_f4;
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_1_ = 0x3c;
  local_d0 = (longlong)(int)dVar7;
  uVar2 = (undefined2)(int)dVar7;
  DAT_cc008000._0_2_ = uVar2;
  local_c8 = (longlong)(int)dVar8;
  uVar3 = (undefined2)(int)dVar8;
  DAT_cc008000._0_2_ = uVar3;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar10;
  DAT_cc008000 = (float)dVar9;
  DAT_cc008000._0_1_ = 0x3c;
  local_c0 = 0x43300000;
  iVar5 = (int)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803dfb80));
  local_b8 = (longlong)iVar5;
  uVar4 = (undefined2)iVar5;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = uVar3;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar11;
  DAT_cc008000 = (float)dVar9;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar4;
  uStack_9c = param_7 * 4 * (param_5 & 0xffff) >> 8;
  local_a0 = 0x43300000;
  iVar5 = (int)(dVar8 + (double)(float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803dfb80));
  local_98 = (longlong)iVar5;
  uVar3 = (undefined2)iVar5;
  DAT_cc008000._0_2_ = uVar3;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar11;
  DAT_cc008000 = (float)dVar6;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = uVar3;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar10;
  DAT_cc008000 = (float)dVar6;
  uStack_bc = uVar1;
  local_b0 = local_c8;
  local_a8 = local_b8;
  local_90 = local_d0;
  local_88 = local_98;
  FUN_8000fb20();
  FUN_80286884();
  return;
}

