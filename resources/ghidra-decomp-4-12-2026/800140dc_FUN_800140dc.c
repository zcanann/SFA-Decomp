// Function: FUN_800140dc
// Entry: 800140dc
// Size: 1388 bytes

/* WARNING: Removing unreachable block (ram,0x80014628) */
/* WARNING: Removing unreachable block (ram,0x800140ec) */

void FUN_800140dc(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar10;
  bool bVar11;
  undefined8 uVar12;
  double dVar13;
  
  FUN_8028683c();
  dVar13 = (double)FLOAT_803dc074;
  bVar1 = false;
  puVar5 = FUN_80017400(0xd);
  if (((DAT_803dd578 & 1) != 0) || (iVar6 = FUN_80020800(), iVar6 != 0)) {
    dVar13 = (double)FLOAT_803df338;
  }
  if ((DAT_803dd579 & 1) == 0) {
    FLOAT_803dd580 = (float)((double)FLOAT_803dd580 + dVar13);
    bVar11 = FLOAT_803dd57c < FLOAT_803dd580;
    if (bVar11) {
      FLOAT_803dd580 = FLOAT_803dd57c;
    }
    if (FLOAT_803dd57c - FLOAT_803df33c < FLOAT_803dd580) {
      bVar1 = true;
    }
  }
  else {
    FLOAT_803dd580 = (float)((double)FLOAT_803dd580 - dVar13);
    bVar11 = FLOAT_803dd580 <= FLOAT_803df338;
    if (bVar11) {
      FLOAT_803dd580 = FLOAT_803df338;
    }
    if (FLOAT_803dd580 < FLOAT_803df33c) {
      bVar1 = true;
    }
  }
  if (bVar11) {
    if ((DAT_803dd579 & 8) != 0) {
      FUN_8000bb38(0,0x28d);
    }
    DAT_803dd578 = DAT_803dd578 & 0xfb | 2;
  }
  if ((DAT_803dd579 & 4) != 0) {
    if (dVar13 != (double)FLOAT_803df338) {
      FUN_8000da78(0,0x28c);
    }
    if ((DAT_803dd579 & 1) == 0) {
      param_3 = (double)(FLOAT_803dd580 / FLOAT_803dd57c);
      uVar2 = ((int)((double)FLOAT_803df340 * param_3) & 0xffU) + 0x2f;
      dVar13 = (double)(float)((double)FLOAT_803df348 * param_3 + (double)FLOAT_803df34c);
    }
    else {
      param_3 = (double)(FLOAT_803dd580 / FLOAT_803dd57c);
      uVar2 = 0x7f - ((int)((double)FLOAT_803df340 * param_3) & 0xffU);
      dVar13 = -(double)(float)((double)FLOAT_803df348 * param_3 - (double)FLOAT_803df344);
    }
    FUN_8000b9bc(dVar13,0,0x28c,
                 (byte)(int)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803df358));
  }
  if ((((DAT_803dd579 & 0x10) != 0) && (DAT_803de400 == '\0')) &&
     (iVar6 = FUN_80020800(), iVar6 == 0)) {
    dVar13 = (double)FLOAT_803dd580;
    iVar6 = (int)FLOAT_803dd580 / 0x3c + ((int)FLOAT_803dd580 >> 0x1f);
    iVar6 = iVar6 - (iVar6 >> 0x1f);
    iVar3 = iVar6 / 0x3c + (iVar6 >> 0x1f);
    iVar3 = iVar3 - (iVar3 >> 0x1f);
    uVar10 = iVar6 + iVar3 * -0x3c;
    iVar6 = (int)(FLOAT_803df350 * (float)(dVar13 / (double)FLOAT_803df354));
    iVar4 = iVar6 / 100 + (iVar6 >> 0x1f);
    iVar6 = iVar6 + (iVar4 - (iVar4 >> 0x1f)) * -100;
    uVar2 = FUN_8013385c();
    uVar8 = 0xff;
    uVar9 = 1;
    FUN_8012c9e8(0x32,(int)(short)((short)uVar2 + -0x2c),0x78,0x28,0xff,1);
    *(short *)(puVar5 + 0x16) = (short)uVar2 + -0x28;
    if ((bVar1) && (iVar6 < 0x32)) {
      uVar7 = 0xff;
      uVar12 = FUN_80019940(0xff,0x40,0x40,0xff);
    }
    else {
      uVar7 = 0xff;
      uVar12 = FUN_80019940(0xff,0xff,0xff,0xff);
    }
    iVar4 = iVar3 / 10 + (iVar3 >> 0x1f);
    FUN_8028fde8(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc5b00,
                 &DAT_803dbef4,iVar4 - (iVar4 >> 0x1f),uVar7,uVar8,uVar9,in_r9,in_r10);
    uVar7 = 3;
    uVar12 = FUN_80015e00(&DAT_8033a500,0xd,5,3);
    iVar4 = iVar3 / 10 + (iVar3 >> 0x1f);
    FUN_8028fde8(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc5b00,
                 &DAT_803dbef4,iVar3 + (iVar4 - (iVar4 >> 0x1f)) * -10,uVar7,uVar8,uVar9,in_r9,
                 in_r10);
    uVar7 = 3;
    uVar12 = FUN_80015e00(&DAT_8033a500,0xd,DAT_803dbedc + 5,3);
    iVar3 = (int)uVar10 / 10 + ((int)uVar10 >> 0x1f);
    FUN_8028fde8(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc5b00,
                 &DAT_803dbef4,iVar3 - (iVar3 >> 0x1f),uVar7,uVar8,uVar9,in_r9,in_r10);
    uVar7 = 3;
    uVar12 = FUN_80015e00(&DAT_8033a500,0xd,DAT_803dbee0 + 5,3);
    iVar3 = (int)uVar10 / 10 + ((int)uVar10 >> 0x1f);
    FUN_8028fde8(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc5b00,
                 &DAT_803dbef4,uVar10 + (iVar3 - (iVar3 >> 0x1f)) * -10,uVar7,uVar8,uVar9,in_r9,
                 in_r10);
    uVar7 = 3;
    uVar12 = FUN_80015e00(&DAT_8033a500,0xd,DAT_803dbee0 + DAT_803dbedc + 5,3);
    iVar3 = iVar6 / 10 + (iVar6 >> 0x1f);
    FUN_8028fde8(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc5b00,
                 &DAT_803dbef4,iVar3 - (iVar3 >> 0x1f),uVar7,uVar8,uVar9,in_r9,in_r10);
    uVar7 = 3;
    uVar12 = FUN_80015e00(&DAT_8033a500,0xd,DAT_803dbee0 * 2 + 5,3);
    iVar3 = iVar6 / 10 + (iVar6 >> 0x1f);
    FUN_8028fde8(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,-0x7fcc5b00,
                 &DAT_803dbef4,iVar6 + (iVar3 - (iVar3 >> 0x1f)) * -10,uVar7,uVar8,uVar9,in_r9,
                 in_r10);
    FUN_80015e00(&DAT_8033a500,0xd,DAT_803dbee0 * 2 + DAT_803dbedc + 5,3);
    if ((uVar10 & 1) != 0) {
      FUN_80015e00(&DAT_803dbefc,0xd,DAT_803dbee4,3);
      FUN_80015e00(&DAT_803dbf00,0xd,DAT_803dbee8,3);
    }
  }
  FUN_80286888();
  return;
}

