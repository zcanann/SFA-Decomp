// Function: FUN_800140bc
// Entry: 800140bc
// Size: 1376 bytes

/* WARNING: Removing unreachable block (ram,0x800145fc) */

void FUN_800140bc(void)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  short sVar7;
  bool bVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_802860d8();
  dVar10 = (double)FLOAT_803db414;
  bVar1 = false;
  iVar5 = FUN_800173c8(0xd);
  if (((DAT_803dc8f8 & 1) != 0) || (iVar6 = FUN_8002073c(), iVar6 != 0)) {
    dVar10 = (double)FLOAT_803de6b8;
  }
  if ((DAT_803dc8f9 & 1) == 0) {
    FLOAT_803dc900 = (float)((double)FLOAT_803dc900 + dVar10);
    bVar8 = FLOAT_803dc8fc < FLOAT_803dc900;
    if (bVar8) {
      FLOAT_803dc900 = FLOAT_803dc8fc;
    }
    if (FLOAT_803dc8fc - FLOAT_803de6bc < FLOAT_803dc900) {
      bVar1 = true;
    }
  }
  else {
    FLOAT_803dc900 = (float)((double)FLOAT_803dc900 - dVar10);
    bVar8 = FLOAT_803dc900 <= FLOAT_803de6b8;
    if (bVar8) {
      FLOAT_803dc900 = FLOAT_803de6b8;
    }
    if (FLOAT_803dc900 < FLOAT_803de6bc) {
      bVar1 = true;
    }
  }
  if (bVar8) {
    if ((DAT_803dc8f9 & 8) != 0) {
      FUN_8000bb18(0,0x28d);
    }
    DAT_803dc8f8 = DAT_803dc8f8 & 0xfb | 2;
  }
  if ((DAT_803dc8f9 & 4) != 0) {
    FUN_8000da58(0,0x28c);
    if ((DAT_803dc8f9 & 1) == 0) {
      uVar2 = ((int)(FLOAT_803de6c0 * (FLOAT_803dc900 / FLOAT_803dc8fc)) & 0xffU) + 0x2f;
      dVar10 = (double)(FLOAT_803de6c8 * (FLOAT_803dc900 / FLOAT_803dc8fc) + FLOAT_803de6cc);
    }
    else {
      uVar2 = 0x7f - ((int)(FLOAT_803de6c0 * (FLOAT_803dc900 / FLOAT_803dc8fc)) & 0xffU);
      dVar10 = -(double)(FLOAT_803de6c8 * (FLOAT_803dc900 / FLOAT_803dc8fc) - FLOAT_803de6c4);
    }
    FUN_8000b99c(dVar10,0,0x28c,
                 (int)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803de6d8));
  }
  if ((((DAT_803dc8f9 & 0x10) != 0) && (DAT_803dd780 == '\0')) &&
     (iVar6 = FUN_8002073c(), iVar6 == 0)) {
    iVar6 = (int)FLOAT_803dc900 / 0x3c + ((int)FLOAT_803dc900 >> 0x1f);
    iVar6 = iVar6 - (iVar6 >> 0x1f);
    iVar3 = iVar6 / 0x3c + (iVar6 >> 0x1f);
    iVar3 = iVar3 - (iVar3 >> 0x1f);
    uVar2 = iVar6 + iVar3 * -0x3c;
    iVar6 = (int)(FLOAT_803de6d0 * (FLOAT_803dc900 / FLOAT_803de6d4));
    iVar4 = iVar6 / 100 + (iVar6 >> 0x1f);
    iVar6 = iVar6 + (iVar4 - (iVar4 >> 0x1f)) * -100;
    sVar7 = FUN_801334d4();
    FUN_8012c6ac(0x32,(int)(short)(sVar7 + -0x2c),0x78,0x28,0xff,1);
    *(short *)(iVar5 + 0x16) = sVar7 + -0x28;
    if ((bVar1) && (iVar6 < 0x32)) {
      FUN_80019908(0xff,0x40,0x40,0xff);
    }
    else {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    iVar5 = iVar3 / 10 + (iVar3 >> 0x1f);
    FUN_8028f688(&DAT_803398a0,&DAT_803db294,iVar5 - (iVar5 >> 0x1f));
    FUN_80015dc8(&DAT_803398a0,0xd,5,3);
    iVar5 = iVar3 / 10 + (iVar3 >> 0x1f);
    FUN_8028f688(&DAT_803398a0,&DAT_803db294,iVar3 + (iVar5 - (iVar5 >> 0x1f)) * -10);
    FUN_80015dc8(&DAT_803398a0,0xd,DAT_803db27c + 5,3);
    iVar5 = (int)uVar2 / 10 + ((int)uVar2 >> 0x1f);
    FUN_8028f688(&DAT_803398a0,&DAT_803db294,iVar5 - (iVar5 >> 0x1f));
    FUN_80015dc8(&DAT_803398a0,0xd,DAT_803db280 + 5,3);
    iVar5 = (int)uVar2 / 10 + ((int)uVar2 >> 0x1f);
    FUN_8028f688(&DAT_803398a0,&DAT_803db294,uVar2 + (iVar5 - (iVar5 >> 0x1f)) * -10);
    FUN_80015dc8(&DAT_803398a0,0xd,DAT_803db280 + DAT_803db27c + 5,3);
    iVar5 = iVar6 / 10 + (iVar6 >> 0x1f);
    FUN_8028f688(&DAT_803398a0,&DAT_803db294,iVar5 - (iVar5 >> 0x1f));
    FUN_80015dc8(&DAT_803398a0,0xd,DAT_803db280 * 2 + 5,3);
    iVar5 = iVar6 / 10 + (iVar6 >> 0x1f);
    FUN_8028f688(&DAT_803398a0,&DAT_803db294,iVar6 + (iVar5 - (iVar5 >> 0x1f)) * -10);
    FUN_80015dc8(&DAT_803398a0,0xd,DAT_803db280 * 2 + DAT_803db27c + 5,3);
    if ((uVar2 & 1) != 0) {
      FUN_80015dc8(&DAT_803db29c,0xd,DAT_803db284,3);
      FUN_80015dc8(&DAT_803db2a0,0xd,DAT_803db288,3);
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_80286124();
  return;
}

