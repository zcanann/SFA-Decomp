// Function: FUN_80108194
// Entry: 80108194
// Size: 744 bytes

void FUN_80108194(short *param_1)

{
  float fVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  double dVar5;
  undefined auStack40 [4];
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  uint uStack20;
  undefined4 local_10;
  uint uStack12;
  
  iVar4 = *(int *)(param_1 + 0x52);
  *(undefined4 *)(DAT_803dd548 + 0x10) = *(undefined4 *)(param_1 + 0xc);
  fVar1 = FLOAT_803e17c4;
  *(float *)(DAT_803dd548 + 0x18) = FLOAT_803e17c4;
  *(float *)(DAT_803dd548 + 0x1c) = fVar1;
  *(undefined4 *)(DAT_803dd548 + 0x20) = *(undefined4 *)(param_1 + 0xe);
  *(float *)(DAT_803dd548 + 0x28) = fVar1;
  *(float *)(DAT_803dd548 + 0x2c) = fVar1;
  *(undefined4 *)(DAT_803dd548 + 0x30) = *(undefined4 *)(param_1 + 0x10);
  *(float *)(DAT_803dd548 + 0x38) = fVar1;
  *(float *)(DAT_803dd548 + 0x3c) = fVar1;
  FUN_80103708(param_1,iVar4,&local_24,auStack40);
  *(undefined4 *)(DAT_803dd548 + 0x14) = local_24;
  *(undefined4 *)(DAT_803dd548 + 0x24) = local_20;
  *(undefined4 *)(DAT_803dd548 + 0x34) = local_1c;
  fVar1 = *(float *)(DAT_803dd548 + 0x14) - *(float *)(DAT_803dd548 + 0x10);
  fVar2 = *(float *)(DAT_803dd548 + 0x34) - *(float *)(DAT_803dd548 + 0x30);
  dVar5 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
  *(float *)(DAT_803dd548 + 0x118) = (float)dVar5;
  *(int *)(DAT_803dd548 + 0xfc) = DAT_803dd548 + 0x40;
  *(int *)(DAT_803dd548 + 0x100) = DAT_803dd548 + 0x50;
  *(undefined4 *)(DAT_803dd548 + 0x104) = 0;
  *(undefined4 *)(DAT_803dd548 + 0x108) = 4;
  *(undefined4 *)(DAT_803dd548 + 0xf8) = 0;
  *(code **)(DAT_803dd548 + 0x10c) = FUN_80010dc0;
  *(undefined **)(DAT_803dd548 + 0x110) = &LAB_80010d54;
  uStack20 = (int)*param_1 ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(DAT_803dd548 + 0x40) = (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e17d8)
  ;
  sVar3 = FUN_800217c0((double)(*(float *)(DAT_803dd548 + 0x14) - *(float *)(iVar4 + 0x18)),
                       (double)(*(float *)(DAT_803dd548 + 0x34) - *(float *)(iVar4 + 0x20)));
  *(float *)(DAT_803dd548 + 0x44) =
       (float)((double)CONCAT44(0x43300000,(int)(short)(-0x8000 - sVar3) ^ 0x80000000) -
              DOUBLE_803e17d8);
  fVar1 = FLOAT_803e17c4;
  *(float *)(DAT_803dd548 + 0x48) = FLOAT_803e17c4;
  *(float *)(DAT_803dd548 + 0x4c) = fVar1;
  fVar1 = *(float *)(DAT_803dd548 + 0x40) - *(float *)(DAT_803dd548 + 0x44);
  if ((FLOAT_803e17c8 < fVar1) || (fVar1 < FLOAT_803e17cc)) {
    if (FLOAT_803e17c4 <= *(float *)(DAT_803dd548 + 0x40)) {
      if (*(float *)(DAT_803dd548 + 0x44) < FLOAT_803e17c4) {
        *(float *)(DAT_803dd548 + 0x44) = *(float *)(DAT_803dd548 + 0x44) + FLOAT_803e17d0;
      }
    }
    else {
      *(float *)(DAT_803dd548 + 0x40) = *(float *)(DAT_803dd548 + 0x40) + FLOAT_803e17d0;
    }
  }
  uStack12 = (int)param_1[1] ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(DAT_803dd548 + 0x50) = (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e17d8)
  ;
  fVar1 = FLOAT_803e17c4;
  *(float *)(DAT_803dd548 + 0x54) = FLOAT_803e17c4;
  *(float *)(DAT_803dd548 + 0x58) = fVar1;
  *(float *)(DAT_803dd548 + 0x5c) = fVar1;
  fVar1 = *(float *)(DAT_803dd548 + 0x50) - *(float *)(DAT_803dd548 + 0x54);
  if ((FLOAT_803e17c8 < fVar1) || (fVar1 < FLOAT_803e17cc)) {
    if (FLOAT_803e17c4 <= *(float *)(DAT_803dd548 + 0x50)) {
      if (*(float *)(DAT_803dd548 + 0x54) < FLOAT_803e17c4) {
        *(float *)(DAT_803dd548 + 0x54) = *(float *)(DAT_803dd548 + 0x54) + FLOAT_803e17d0;
      }
    }
    else {
      *(float *)(DAT_803dd548 + 0x50) = *(float *)(DAT_803dd548 + 0x50) + FLOAT_803e17d0;
    }
  }
  FUN_80010a6c(DAT_803dd548 + 0x78);
  return;
}

