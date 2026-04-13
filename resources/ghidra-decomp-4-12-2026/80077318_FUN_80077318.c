// Function: FUN_80077318
// Entry: 80077318
// Size: 1128 bytes

/* WARNING: Removing unreachable block (ram,0x80077760) */
/* WARNING: Removing unreachable block (ram,0x80077758) */
/* WARNING: Removing unreachable block (ram,0x80077330) */
/* WARNING: Removing unreachable block (ram,0x80077328) */

void FUN_80077318(double param_1,double param_2,int param_3,uint param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  undefined2 uVar3;
  undefined2 uVar4;
  undefined2 uVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  undefined4 local_88;
  undefined4 local_84;
  longlong local_80;
  longlong local_78;
  undefined4 local_70;
  int iStack_6c;
  longlong local_68;
  longlong local_60;
  longlong local_58;
  undefined4 local_50;
  int iStack_4c;
  longlong local_48;
  longlong local_40;
  longlong local_38;
  
  local_84 = CONCAT31(0xffffff,(char)((param_4 & 0xff) * (uint)DAT_803dc2d9 >> 8));
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  local_88 = local_84;
  FUN_8025c510(0,(byte *)&local_88);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,8);
  FUN_8025c224(0,7,4,6,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  if (*(int *)(param_3 + 0x50) == 0) {
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
  FUN_8004c3e0(param_3,0);
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
  uVar2 = (uint)*(ushort *)(param_3 + 10) * 4 * (param_5 & 0xffff);
  iVar7 = ((int)uVar2 >> 8) + (uint)((int)uVar2 < 0 && (uVar2 & 0xff) != 0);
  uVar2 = (uint)*(ushort *)(param_3 + 0xc) * 4 * (param_5 & 0xffff);
  iVar6 = ((int)uVar2 >> 8) + (uint)((int)uVar2 < 0 && (uVar2 & 0xff) != 0);
  dVar8 = (double)(float)((double)FLOAT_803dfbac * param_1);
  dVar9 = (double)(float)((double)FLOAT_803dfbac * param_2);
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_1_ = 0x3c;
  local_80 = (longlong)(int)dVar8;
  uVar3 = (undefined2)(int)dVar8;
  DAT_cc008000._0_2_ = uVar3;
  local_78 = (longlong)(int)dVar9;
  uVar4 = (undefined2)(int)dVar9;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  local_70 = 0x43300000;
  iVar1 = (int)(dVar8 + (double)(float)((double)CONCAT44(0x43300000,iVar7) - DOUBLE_803dfb80));
  local_68 = (longlong)iVar1;
  uVar5 = (undefined2)iVar1;
  DAT_cc008000._0_2_ = uVar5;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb64;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar5;
  local_50 = 0x43300000;
  iVar1 = (int)(dVar9 + (double)(float)((double)CONCAT44(0x43300000,iVar6) - DOUBLE_803dfb80));
  local_48 = (longlong)iVar1;
  uVar4 = (undefined2)iVar1;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb64;
  DAT_cc008000 = FLOAT_803dfb64;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar3;
  DAT_cc008000._0_2_ = uVar4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb64;
  iStack_6c = iVar7;
  local_60 = local_78;
  local_58 = local_68;
  iStack_4c = iVar6;
  local_40 = local_80;
  local_38 = local_48;
  FUN_8000fb20();
  return;
}

