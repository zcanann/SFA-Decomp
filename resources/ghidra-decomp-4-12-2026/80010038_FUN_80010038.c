// Function: FUN_80010038
// Entry: 80010038
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x80010320) */
/* WARNING: Removing unreachable block (ram,0x80010318) */
/* WARNING: Removing unreachable block (ram,0x80010310) */
/* WARNING: Removing unreachable block (ram,0x80010308) */
/* WARNING: Removing unreachable block (ram,0x80010300) */
/* WARNING: Removing unreachable block (ram,0x800102f8) */
/* WARNING: Removing unreachable block (ram,0x800102f0) */
/* WARNING: Removing unreachable block (ram,0x800102e8) */
/* WARNING: Removing unreachable block (ram,0x800102e0) */
/* WARNING: Removing unreachable block (ram,0x800102d8) */
/* WARNING: Removing unreachable block (ram,0x800102d0) */
/* WARNING: Removing unreachable block (ram,0x800102c8) */

void FUN_80010038(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,float *param_5,
                 float *param_6,uint param_7,undefined *param_8)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  double dVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint unaff_GQR0;
  double in_f20;
  double in_f21;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps20_1;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar8;
  float local_118;
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_b8;
  float fStack_b4;
  undefined4 local_a8;
  float fStack_a4;
  undefined4 local_98;
  float fStack_94;
  undefined4 local_88;
  float fStack_84;
  undefined4 local_78;
  float fStack_74;
  undefined4 local_68;
  float fStack_64;
  undefined4 local_58;
  float fStack_54;
  undefined4 local_48;
  float fStack_44;
  undefined4 local_38;
  float fStack_34;
  undefined4 local_28;
  float fStack_24;
  undefined4 local_18;
  float fStack_14;
  undefined4 local_8;
  float fStack_4;
  
  bVar1 = (byte)unaff_GQR0;
  bVar2 = bVar1 & 7;
  bVar3 = (byte)(unaff_GQR0 >> 8);
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_8 = (float)CONCAT13((char)(dVar4 * in_f31),
                              CONCAT12((char)(dVar4 * in_ps31_1),local_8._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_8 = (float)CONCAT22((short)(dVar4 * in_f31),(short)(dVar4 * in_ps31_1));
  }
  else {
    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_18 = (float)CONCAT13((char)(dVar4 * in_f30),
                               CONCAT12((char)(dVar4 * in_ps30_1),local_18._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_18 = (float)CONCAT22((short)(dVar4 * in_f30),(short)(dVar4 * in_ps30_1));
  }
  else {
    local_18 = (float)in_f30;
    fStack_14 = (float)in_ps30_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_28 = (float)CONCAT13((char)(dVar4 * in_f29),
                               CONCAT12((char)(dVar4 * in_ps29_1),local_28._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_28 = (float)CONCAT22((short)(dVar4 * in_f29),(short)(dVar4 * in_ps29_1));
  }
  else {
    local_28 = (float)in_f29;
    fStack_24 = (float)in_ps29_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_38 = (float)CONCAT13((char)(dVar4 * in_f28),
                               CONCAT12((char)(dVar4 * in_ps28_1),local_38._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_38 = (float)CONCAT22((short)(dVar4 * in_f28),(short)(dVar4 * in_ps28_1));
  }
  else {
    local_38 = (float)in_f28;
    fStack_34 = (float)in_ps28_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_48 = (float)CONCAT13((char)(dVar4 * in_f27),
                               CONCAT12((char)(dVar4 * in_ps27_1),local_48._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_48 = (float)CONCAT22((short)(dVar4 * in_f27),(short)(dVar4 * in_ps27_1));
  }
  else {
    local_48 = (float)in_f27;
    fStack_44 = (float)in_ps27_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_58 = (float)CONCAT13((char)(dVar4 * in_f26),
                               CONCAT12((char)(dVar4 * in_ps26_1),local_58._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_58 = (float)CONCAT22((short)(dVar4 * in_f26),(short)(dVar4 * in_ps26_1));
  }
  else {
    local_58 = (float)in_f26;
    fStack_54 = (float)in_ps26_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_68 = (float)CONCAT13((char)(dVar4 * in_f25),
                               CONCAT12((char)(dVar4 * in_ps25_1),local_68._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_68 = (float)CONCAT22((short)(dVar4 * in_f25),(short)(dVar4 * in_ps25_1));
  }
  else {
    local_68 = (float)in_f25;
    fStack_64 = (float)in_ps25_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_78 = (float)CONCAT13((char)(dVar4 * in_f24),
                               CONCAT12((char)(dVar4 * in_ps24_1),local_78._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_78 = (float)CONCAT22((short)(dVar4 * in_f24),(short)(dVar4 * in_ps24_1));
  }
  else {
    local_78 = (float)in_f24;
    fStack_74 = (float)in_ps24_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_88 = (float)CONCAT13((char)(dVar4 * in_f23),
                               CONCAT12((char)(dVar4 * in_ps23_1),local_88._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_88 = (float)CONCAT22((short)(dVar4 * in_f23),(short)(dVar4 * in_ps23_1));
  }
  else {
    local_88 = (float)in_f23;
    fStack_84 = (float)in_ps23_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_98 = (float)CONCAT13((char)(dVar4 * in_f22),
                               CONCAT12((char)(dVar4 * in_ps22_1),local_98._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_98 = (float)CONCAT22((short)(dVar4 * in_f22),(short)(dVar4 * in_ps22_1));
  }
  else {
    local_98 = (float)in_f22;
    fStack_94 = (float)in_ps22_1;
  }
  bVar2 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_a8 = (float)CONCAT13((char)(dVar4 * in_f21),
                               CONCAT12((char)(dVar4 * in_ps21_1),local_a8._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_a8 = (float)CONCAT22((short)(dVar4 * in_f21),(short)(dVar4 * in_ps21_1));
  }
  else {
    local_a8 = (float)in_f21;
    fStack_a4 = (float)in_ps21_1;
  }
  bVar1 = bVar1 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar1 == 4 || bVar1 == 6) {
    local_b8 = (float)CONCAT13((char)(dVar4 * in_f20),
                               CONCAT12((char)(dVar4 * in_ps20_1),local_b8._2_2_));
  }
  else if (bVar1 == 5 || bVar1 == 7) {
    local_b8 = (float)CONCAT22((short)(dVar4 * in_f20),(short)(dVar4 * in_ps20_1));
  }
  else {
    local_b8 = (float)in_f20;
    fStack_b4 = (float)in_ps20_1;
  }
  uVar8 = FUN_80286834();
  iVar6 = (int)((ulonglong)uVar8 >> 0x20);
  iVar7 = (int)uVar8;
  if (param_7 != DAT_803dbed0) {
    uStack_e4 = param_7 ^ 0x80000000;
    local_e8 = 0x43300000;
    FLOAT_803dd530 =
         FLOAT_803df2f4 / (float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803df308);
    DAT_803393f0 = FLOAT_803dd530 * FLOAT_803dd530;
    DAT_803393f4 = FLOAT_803df2e0 * DAT_803393f0;
    DAT_803393f8 = FLOAT_803dd530 * DAT_803393f0;
    DAT_803393fc = FLOAT_803df300 * DAT_803393f8;
    DAT_803dbed0 = param_7;
  }
  if (iVar6 != 0) {
    (*(code *)param_8)(iVar6,&local_f8);
    in_f31 = (double)local_ec;
    in_f30 = (double)(FLOAT_803dd530 * local_f0 +
                     DAT_803393f8 * local_f8 + (float)((double)DAT_803393f0 * (double)local_f4));
    in_f28 = (double)(DAT_803393fc * local_f8);
    in_f29 = (double)(float)((double)DAT_803393f4 * (double)local_f4 + in_f28);
  }
  if (iVar7 != 0) {
    (*(code *)param_8)(iVar7,&local_108);
    in_f27 = (double)local_fc;
    in_f26 = (double)(FLOAT_803dd530 * local_100 +
                     DAT_803393f8 * local_108 + (float)((double)DAT_803393f0 * (double)local_104));
    in_f24 = (double)(DAT_803393fc * local_108);
    in_f25 = (double)(float)((double)DAT_803393f4 * (double)local_104 + in_f24);
  }
  if (param_3 != 0) {
    (*(code *)param_8)(param_3,&local_118);
    in_f23 = (double)local_10c;
    in_f22 = (double)(FLOAT_803dd530 * local_110 +
                     DAT_803393f8 * local_118 + (float)((double)DAT_803393f0 * (double)local_114));
    in_f20 = (double)(DAT_803393fc * local_118);
    in_f21 = (double)(float)((double)DAT_803393f4 * (double)local_114 + in_f20);
  }
  iVar5 = param_7 + 1;
  if (-1 < (int)param_7) {
    do {
      if (iVar6 != 0) {
        *param_4 = (float)in_f31;
        in_f31 = (double)(float)(in_f31 + in_f30);
        in_f30 = (double)(float)(in_f30 + in_f29);
        in_f29 = (double)(float)(in_f29 + in_f28);
      }
      if (iVar7 != 0) {
        *param_5 = (float)in_f27;
        in_f27 = (double)(float)(in_f27 + in_f26);
        in_f26 = (double)(float)(in_f26 + in_f25);
        in_f25 = (double)(float)(in_f25 + in_f24);
      }
      if (param_3 != 0) {
        *param_6 = (float)in_f23;
        in_f23 = (double)(float)(in_f23 + in_f22);
        in_f22 = (double)(float)(in_f22 + in_f21);
        in_f21 = (double)(float)(in_f21 + in_f20);
      }
      param_4 = param_4 + 1;
      param_5 = param_5 + 1;
      param_6 = param_6 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  bVar1 = (byte)(unaff_GQR0 >> 0x18);
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  FUN_80286880();
  return;
}

