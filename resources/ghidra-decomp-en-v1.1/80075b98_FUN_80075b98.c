// Function: FUN_80075b98
// Entry: 80075b98
// Size: 832 bytes

/* WARNING: Removing unreachable block (ram,0x80075ebc) */
/* WARNING: Removing unreachable block (ram,0x80075eb4) */
/* WARNING: Removing unreachable block (ram,0x80075eac) */
/* WARNING: Removing unreachable block (ram,0x80075ea4) */
/* WARNING: Removing unreachable block (ram,0x80075e9c) */
/* WARNING: Removing unreachable block (ram,0x80075e94) */
/* WARNING: Removing unreachable block (ram,0x80075bd0) */
/* WARNING: Removing unreachable block (ram,0x80075bc8) */
/* WARNING: Removing unreachable block (ram,0x80075bc0) */
/* WARNING: Removing unreachable block (ram,0x80075bb8) */
/* WARNING: Removing unreachable block (ram,0x80075bb0) */
/* WARNING: Removing unreachable block (ram,0x80075ba8) */

void FUN_80075b98(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined4 *param_7)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined4 local_a8 [2];
  longlong local_a0;
  longlong local_98;
  longlong local_90;
  longlong local_88;
  longlong local_80;
  longlong local_78;
  
  dVar1 = (double)FLOAT_803dfbac;
  dVar2 = (double)(float)(dVar1 * param_1);
  dVar3 = (double)(float)(dVar1 * param_2);
  dVar4 = (double)(float)(dVar1 * param_3);
  dVar5 = (double)(float)(dVar1 * param_4);
  dVar6 = (double)(float)(dVar1 * param_5);
  dVar1 = (double)(float)(dVar1 * param_6);
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
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
  *(char *)((int)param_7 + 3) = (char)((uint)*(byte *)((int)param_7 + 3) * (uint)DAT_803dc2d9 >> 8);
  local_a8[0] = *param_7;
  FUN_8025c510(0,(byte *)local_a8);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c584(0,0xc);
  FUN_8025c828(0,0xff,0xff,4);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  FUN_8025c224(0,7,7,7,6);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025a608(0,0,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025a5bc(1);
  FUN_8025be54(0);
  FUN_80258944(0);
  FUN_8025ca04(1);
  FUN_80259000(0x90,1,3);
  DAT_cc008000._0_1_ = 0x3c;
  local_a0 = (longlong)(int)dVar2;
  DAT_cc008000._0_2_ = (short)(int)dVar2;
  local_98 = (longlong)(int)dVar3;
  DAT_cc008000._0_2_ = (short)(int)dVar3;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  local_90 = (longlong)(int)dVar4;
  DAT_cc008000._0_2_ = (short)(int)dVar4;
  local_88 = (longlong)(int)dVar5;
  DAT_cc008000._0_2_ = (short)(int)dVar5;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  local_80 = (longlong)(int)dVar6;
  DAT_cc008000._0_2_ = (short)(int)dVar6;
  local_78 = (longlong)(int)dVar1;
  DAT_cc008000._0_2_ = (short)(int)dVar1;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  FUN_8000fb20();
  return;
}

