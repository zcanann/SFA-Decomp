// Function: FUN_80075800
// Entry: 80075800
// Size: 920 bytes

/* WARNING: Removing unreachable block (ram,0x80075b7c) */
/* WARNING: Removing unreachable block (ram,0x80075b74) */
/* WARNING: Removing unreachable block (ram,0x80075b6c) */
/* WARNING: Removing unreachable block (ram,0x80075b64) */
/* WARNING: Removing unreachable block (ram,0x80075b5c) */
/* WARNING: Removing unreachable block (ram,0x80075b54) */
/* WARNING: Removing unreachable block (ram,0x80075b4c) */
/* WARNING: Removing unreachable block (ram,0x80075b44) */
/* WARNING: Removing unreachable block (ram,0x80075848) */
/* WARNING: Removing unreachable block (ram,0x80075840) */
/* WARNING: Removing unreachable block (ram,0x80075838) */
/* WARNING: Removing unreachable block (ram,0x80075830) */
/* WARNING: Removing unreachable block (ram,0x80075828) */
/* WARNING: Removing unreachable block (ram,0x80075820) */
/* WARNING: Removing unreachable block (ram,0x80075818) */
/* WARNING: Removing unreachable block (ram,0x80075810) */

void FUN_80075800(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,double param_8,undefined4 *param_9)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined4 local_d8 [2];
  longlong local_d0;
  longlong local_c8;
  longlong local_c0;
  longlong local_b8;
  longlong local_b0;
  longlong local_a8;
  longlong local_a0;
  longlong local_98;
  
  dVar1 = (double)FLOAT_803dfbac;
  dVar2 = (double)(float)(dVar1 * param_1);
  dVar3 = (double)(float)(dVar1 * param_2);
  dVar4 = (double)(float)(dVar1 * param_3);
  dVar5 = (double)(float)(dVar1 * param_4);
  dVar6 = (double)(float)(dVar1 * param_5);
  dVar7 = (double)(float)(dVar1 * param_6);
  dVar8 = (double)(float)(dVar1 * param_7);
  dVar1 = (double)(float)(dVar1 * param_8);
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
  *(char *)((int)param_9 + 3) = (char)((uint)*(byte *)((int)param_9 + 3) * (uint)DAT_803dc2d9 >> 8);
  local_d8[0] = *param_9;
  FUN_8025c510(0,(byte *)local_d8);
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
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_1_ = 0x3c;
  local_d0 = (longlong)(int)dVar2;
  DAT_cc008000._0_2_ = (short)(int)dVar2;
  local_c8 = (longlong)(int)dVar3;
  DAT_cc008000._0_2_ = (short)(int)dVar3;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  local_c0 = (longlong)(int)dVar4;
  DAT_cc008000._0_2_ = (short)(int)dVar4;
  local_b8 = (longlong)(int)dVar5;
  DAT_cc008000._0_2_ = (short)(int)dVar5;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  local_b0 = (longlong)(int)dVar6;
  DAT_cc008000._0_2_ = (short)(int)dVar6;
  local_a8 = (longlong)(int)dVar7;
  DAT_cc008000._0_2_ = (short)(int)dVar7;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  local_a0 = (longlong)(int)dVar8;
  DAT_cc008000._0_2_ = (short)(int)dVar8;
  local_98 = (longlong)(int)dVar1;
  DAT_cc008000._0_2_ = (short)(int)dVar1;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  FUN_8000fb20();
  return;
}

