// Function: FUN_80076998
// Entry: 80076998
// Size: 1372 bytes

/* WARNING: Removing unreachable block (ram,0x80076ed4) */
/* WARNING: Removing unreachable block (ram,0x80076ecc) */
/* WARNING: Removing unreachable block (ram,0x80076ec4) */
/* WARNING: Removing unreachable block (ram,0x80076ebc) */
/* WARNING: Removing unreachable block (ram,0x80076eb4) */
/* WARNING: Removing unreachable block (ram,0x80076eac) */
/* WARNING: Removing unreachable block (ram,0x800769d0) */
/* WARNING: Removing unreachable block (ram,0x800769c8) */
/* WARNING: Removing unreachable block (ram,0x800769c0) */
/* WARNING: Removing unreachable block (ram,0x800769b8) */
/* WARNING: Removing unreachable block (ram,0x800769b0) */
/* WARNING: Removing unreachable block (ram,0x800769a8) */

void FUN_80076998(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,uint param_8)

{
  uint uVar1;
  uint uVar2;
  undefined2 uVar3;
  undefined2 uVar4;
  undefined2 uVar5;
  int iVar6;
  double dVar7;
  double extraout_f1;
  double dVar8;
  double in_f26;
  double in_f27;
  double dVar9;
  double in_f28;
  double dVar10;
  double in_f29;
  double dVar11;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  undefined4 local_d8;
  undefined4 local_d4;
  undefined8 local_d0;
  undefined4 local_c8;
  uint uStack_c4;
  undefined8 local_c0;
  undefined8 local_b8;
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
  uVar14 = FUN_8028683c();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  local_d4 = CONCAT31(0xffffff,(char)(((uint)uVar14 & 0xff) * (uint)DAT_803dc2d9 >> 8));
  dVar7 = extraout_f1;
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  local_d8 = local_d4;
  FUN_8025c510(0,(byte *)&local_d8);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,8);
  FUN_8025c224(0,7,4,6,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  if (*(int *)(iVar6 + 0x50) == 0) {
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
  FUN_8004c3e0(iVar6,0);
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
  if ((param_8 & 4) == 0) {
    FUN_8025cce8(1,4,5,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  uVar1 = param_6 * 4 * (param_5 & 0xffff) >> 8;
  uVar2 = param_7 * 4 * (param_5 & 0xffff) >> 8;
  dVar12 = (double)(float)((double)FLOAT_803dfbac * dVar7);
  dVar13 = (double)(float)((double)FLOAT_803dfbac * param_2);
  local_d0 = (double)CONCAT44(0x43300000,param_6);
  uStack_c4 = (uint)*(ushort *)(iVar6 + 10);
  local_c8 = 0x43300000;
  dVar8 = (double)((float)(local_d0 - DOUBLE_803dfb80) /
                  (float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803dfb80));
  local_c0 = (double)CONCAT44(0x43300000,param_7);
  local_b8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar6 + 0xc));
  dVar7 = (double)((float)(local_c0 - DOUBLE_803dfb80) / (float)(local_b8 - DOUBLE_803dfb80));
  if ((param_8 & 1) == 0) {
    dVar11 = (double)FLOAT_803dfb5c;
    dVar10 = dVar8;
  }
  else {
    dVar10 = (double)FLOAT_803dfb5c;
    dVar11 = dVar8;
  }
  if ((param_8 & 2) == 0) {
    dVar9 = (double)FLOAT_803dfb5c;
    dVar8 = dVar7;
  }
  else {
    dVar8 = (double)FLOAT_803dfb5c;
    dVar9 = dVar7;
  }
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_1_ = 0x3c;
  local_b8 = (double)(longlong)(int)dVar12;
  uVar3 = (undefined2)(int)dVar12;
  DAT_cc008000._0_2_ = uVar3;
  local_c0 = (double)(longlong)(int)dVar13;
  uVar4 = (undefined2)(int)dVar13;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar11;
  DAT_cc008000 = (float)dVar9;
  DAT_cc008000._0_1_ = 0x3c;
  local_c8 = 0x43300000;
  iVar6 = (int)(dVar12 + (double)(float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803dfb80));
  local_d0 = (double)(longlong)iVar6;
  uVar5 = (undefined2)iVar6;
  DAT_cc008000._0_2_ = uVar5;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar10;
  DAT_cc008000 = (float)dVar9;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar5;
  local_a0 = 0x43300000;
  iVar6 = (int)(dVar13 + (double)(float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803dfb80));
  local_98 = (longlong)iVar6;
  uVar4 = (undefined2)iVar6;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar10;
  DAT_cc008000 = (float)dVar8;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar3;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar11;
  DAT_cc008000 = (float)dVar8;
  uStack_c4 = uVar1;
  local_b0 = (longlong)local_c0;
  local_a8 = (longlong)local_d0;
  uStack_9c = uVar2;
  local_90 = (longlong)local_b8;
  local_88 = local_98;
  FUN_8000fb20();
  FUN_80286888();
  return;
}

