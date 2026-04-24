// Function: FUN_8010847c
// Entry: 8010847c
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x8010884c) */
/* WARNING: Removing unreachable block (ram,0x80108854) */

void FUN_8010847c(short *param_1)

{
  float fVar1;
  short sVar2;
  char cVar3;
  char cVar4;
  short *psVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar8;
  double local_38;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  psVar5 = *(short **)(param_1 + 0x52);
  cVar3 = FUN_80014cc0(0);
  cVar4 = FUN_80014c6c(0);
  dVar7 = (double)((FLOAT_803e17e0 - *(float *)(param_1 + 0x5a)) / FLOAT_803e17e4);
  dVar8 = (double)FLOAT_803e17c4;
  if ((dVar8 <= dVar7) && (dVar8 = dVar7, (double)FLOAT_803e17e8 < dVar7)) {
    dVar8 = (double)FLOAT_803e17e8;
  }
  dVar7 = (double)FUN_80021370((double)((float)((double)CONCAT44(0x43300000,(int)cVar3 ^ 0x80000000)
                                               - DOUBLE_803e17d8) *
                                        -(float)((double)FLOAT_803e17f0 * dVar8 -
                                                (double)FLOAT_803e17ec) -
                                       *(float *)(DAT_803dd548 + 0x11c)),(double)FLOAT_803e17f4,
                               (double)FLOAT_803db414);
  *(float *)(DAT_803dd548 + 0x11c) = (float)((double)*(float *)(DAT_803dd548 + 0x11c) + dVar7);
  if ((FLOAT_803e17f8 < *(float *)(DAT_803dd548 + 0x11c)) &&
     (*(float *)(DAT_803dd548 + 0x11c) < FLOAT_803e17fc)) {
    *(float *)(DAT_803dd548 + 0x11c) = FLOAT_803e17c4;
  }
  fVar1 = FLOAT_803e1800 *
          ((float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) - DOUBLE_803e17d8) /
          FLOAT_803e1804);
  *param_1 = (short)(int)(*(float *)(DAT_803dd548 + 0x11c) * FLOAT_803db414 +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                DOUBLE_803e17d8));
  sVar2 = (short)(int)fVar1 - param_1[1];
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  dVar8 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,(int)sVar2 ^ 0x80000000)
                                              - DOUBLE_803e17d8),
                               (double)(FLOAT_803e17e8 /
                                       (float)((double)FLOAT_803e180c * dVar8 +
                                              (double)FLOAT_803e1808)),(double)FLOAT_803db414);
  param_1[1] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000
                                                            ) - DOUBLE_803e17d8) + dVar8);
  if (0x3c00 < param_1[1]) {
    param_1[1] = 0x3c00;
  }
  if (param_1[1] < -0x3c00) {
    param_1[1] = -0x3c00;
  }
  *psVar5 = -0x8000 - *param_1;
  if (psVar5[0x22] == 1) {
    FUN_802961d4(psVar5,(int)*psVar5);
  }
  if (*(float *)(DAT_803dd548 + 0x124) < *(float *)(DAT_803dd548 + 0x130)) {
    *(float *)(DAT_803dd548 + 0x130) = *(float *)(DAT_803dd548 + 0x124);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(DAT_803dd548 + 0x120);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(DAT_803dd548 + 0x130);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(DAT_803dd548 + 0x128);
  if (*(char *)(DAT_803dd548 + 0x12d) < '\0') {
    dVar8 = (double)*(float *)(param_1 + 0x5a);
    cVar3 = FUN_80014bc4(0);
    local_38 = (double)CONCAT44(0x43300000,-(int)cVar3 ^ 0x80000000);
    dVar7 = (double)(float)((double)(FLOAT_803e1810 * (float)(local_38 - DOUBLE_803e17d8)) *
                            (double)FLOAT_803db414 + dVar8);
    FUN_8000fc34();
    FUN_80096994();
    dVar8 = (double)FLOAT_803e17fc;
    if ((dVar8 <= dVar7) && (dVar8 = dVar7, (double)FLOAT_803e17e0 < dVar7)) {
      dVar8 = (double)FLOAT_803e17e0;
    }
    if ((*(byte *)(DAT_803dd548 + 0x12d) >> 6 & 1) != 0) {
      if ((dVar8 == (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(DAT_803dd548 + 0x12d) >> 5 & 1) != 0)) {
        FUN_8000b824(0,0x3d8);
        *(byte *)(DAT_803dd548 + 0x12d) = *(byte *)(DAT_803dd548 + 0x12d) & 0xdf;
      }
      if ((dVar8 != (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(DAT_803dd548 + 0x12d) >> 5 & 1) == 0)) {
        FUN_8000bb18(0,0x3d8);
        *(byte *)(DAT_803dd548 + 0x12d) = *(byte *)(DAT_803dd548 + 0x12d) & 0xdf | 0x20;
      }
    }
    *(float *)(param_1 + 0x5a) = (float)dVar8;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

