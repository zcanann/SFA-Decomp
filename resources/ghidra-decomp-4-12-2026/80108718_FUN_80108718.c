// Function: FUN_80108718
// Entry: 80108718
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x80108af0) */
/* WARNING: Removing unreachable block (ram,0x80108ae8) */
/* WARNING: Removing unreachable block (ram,0x80108730) */
/* WARNING: Removing unreachable block (ram,0x80108728) */

void FUN_80108718(short *param_1)

{
  float fVar1;
  short sVar2;
  char cVar3;
  char cVar4;
  short *psVar5;
  double dVar6;
  double dVar7;
  undefined8 local_38;
  
  psVar5 = *(short **)(param_1 + 0x52);
  cVar3 = FUN_80014cec(0);
  cVar4 = FUN_80014c98(0);
  dVar6 = (double)((FLOAT_803e2460 - *(float *)(param_1 + 0x5a)) / FLOAT_803e2464);
  dVar7 = (double)FLOAT_803e2444;
  if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)FLOAT_803e2468 < dVar6)) {
    dVar7 = (double)FLOAT_803e2468;
  }
  dVar6 = FUN_80021434((double)((float)((double)CONCAT44(0x43300000,(int)cVar3 ^ 0x80000000) -
                                       DOUBLE_803e2458) *
                                -(float)((double)FLOAT_803e2470 * dVar7 - (double)FLOAT_803e246c) -
                               *(float *)(DAT_803de1c0 + 0x11c)),(double)FLOAT_803e2474,
                       (double)FLOAT_803dc074);
  *(float *)(DAT_803de1c0 + 0x11c) = (float)((double)*(float *)(DAT_803de1c0 + 0x11c) + dVar6);
  if ((FLOAT_803e2478 < *(float *)(DAT_803de1c0 + 0x11c)) &&
     (*(float *)(DAT_803de1c0 + 0x11c) < FLOAT_803e247c)) {
    *(float *)(DAT_803de1c0 + 0x11c) = FLOAT_803e2444;
  }
  fVar1 = FLOAT_803e2480 *
          ((float)((double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000) - DOUBLE_803e2458) /
          FLOAT_803e2484);
  *param_1 = (short)(int)(*(float *)(DAT_803de1c0 + 0x11c) * FLOAT_803dc074 +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                DOUBLE_803e2458));
  sVar2 = (short)(int)fVar1 - param_1[1];
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  dVar7 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,(int)sVar2 ^ 0x80000000) -
                                      DOUBLE_803e2458),
                       (double)(FLOAT_803e2468 /
                               (float)((double)FLOAT_803e248c * dVar7 + (double)FLOAT_803e2488)),
                       (double)FLOAT_803dc074);
  param_1[1] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000
                                                            ) - DOUBLE_803e2458) + dVar7);
  if (0x3c00 < param_1[1]) {
    param_1[1] = 0x3c00;
  }
  if (param_1[1] < -0x3c00) {
    param_1[1] = -0x3c00;
  }
  *psVar5 = -0x8000 - *param_1;
  if (psVar5[0x22] == 1) {
    FUN_80296934(psVar5,*psVar5);
  }
  if (*(float *)(DAT_803de1c0 + 0x124) < *(float *)(DAT_803de1c0 + 0x130)) {
    *(float *)(DAT_803de1c0 + 0x130) = *(float *)(DAT_803de1c0 + 0x124);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(DAT_803de1c0 + 0x120);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(DAT_803de1c0 + 0x130);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(DAT_803de1c0 + 0x128);
  if (*(char *)(DAT_803de1c0 + 0x12d) < '\0') {
    dVar7 = (double)*(float *)(param_1 + 0x5a);
    cVar3 = FUN_80014bf0(0);
    local_38 = (double)CONCAT44(0x43300000,-(int)cVar3 ^ 0x80000000);
    dVar6 = (double)(float)((double)(FLOAT_803e2490 * (float)(local_38 - DOUBLE_803e2458)) *
                            (double)FLOAT_803dc074 + dVar7);
    dVar7 = FUN_8000fc54();
    FUN_80096c20(dVar7);
    dVar7 = (double)FLOAT_803e247c;
    if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)FLOAT_803e2460 < dVar6)) {
      dVar7 = (double)FLOAT_803e2460;
    }
    if ((*(byte *)(DAT_803de1c0 + 0x12d) >> 6 & 1) != 0) {
      if ((dVar7 == (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(DAT_803de1c0 + 0x12d) >> 5 & 1) != 0)) {
        FUN_8000b844(0,0x3d8);
        *(byte *)(DAT_803de1c0 + 0x12d) = *(byte *)(DAT_803de1c0 + 0x12d) & 0xdf;
      }
      if ((dVar7 != (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(DAT_803de1c0 + 0x12d) >> 5 & 1) == 0)) {
        FUN_8000bb38(0,0x3d8);
        *(byte *)(DAT_803de1c0 + 0x12d) = *(byte *)(DAT_803de1c0 + 0x12d) & 0xdf | 0x20;
      }
    }
    *(float *)(param_1 + 0x5a) = (float)dVar7;
  }
  return;
}

