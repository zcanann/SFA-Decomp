// Function: FUN_802bdf1c
// Entry: 802bdf1c
// Size: 1056 bytes

void FUN_802bdf1c(void)

{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short sVar5;
  int iVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar11;
  
  uVar11 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  iVar7 = *(int *)(iVar4 + 0xb8);
  if (*(char *)(iVar6 + 0x27a) != '\0') {
    *(float *)(iVar6 + 0x294) = FLOAT_803e8f9c;
  }
  dVar9 = (double)*(float *)(iVar7 + 0x1384);
  dVar10 = (double)FLOAT_803dc074;
  dVar8 = FUN_80021434((double)*(float *)(iVar6 + 0x280),dVar9,dVar10);
  *(float *)(iVar6 + 0x280) = (float)((double)*(float *)(iVar6 + 0x280) - dVar8);
  if (*(float *)(iVar6 + 0x280) <= DAT_80335ee4) {
    *(float *)(iVar6 + 0x280) = FLOAT_803e8f9c;
  }
  fVar2 = FLOAT_803e8f9c;
  *(float *)(iVar6 + 0x284) = FLOAT_803e8f9c;
  *(float *)(iVar4 + 0x24) = fVar2;
  *(float *)(iVar4 + 0x2c) = fVar2;
  if (((((char)*(byte *)(iVar7 + 0xf48) < '\0') || ((*(byte *)(iVar7 + 0xf48) >> 6 & 1) != 0)) ||
      ((*(byte *)(iVar7 + 0x14ec) & 1) != 0)) || ((*(uint *)(iVar6 + 0x31c) & 0x100) == 0)) {
    if (((*(float *)(iVar6 + 0x29c) < FLOAT_803e8ff0) ||
        (*(float *)(iVar6 + 0x298) < FLOAT_803e8ff0)) ||
       (*(float *)(iVar6 + 0x294) < *(float *)(*(int *)(iVar7 + 0xf58) + 4))) {
      sVar1 = **(short **)(iVar7 + 0xf50);
      *(undefined2 *)(iVar6 + 0x278) = 0;
      *(float *)(iVar7 + 0xf5c) = FLOAT_803e8f80;
      fVar2 = (*(float *)(iVar6 + 0x298) - FLOAT_803e8fa0) / FLOAT_803e8f94;
      fVar3 = FLOAT_803e8f9c;
      if ((FLOAT_803e8f9c <= fVar2) && (fVar3 = fVar2, FLOAT_803e8fd0 < fVar2)) {
        fVar3 = FLOAT_803e8fd0;
      }
      *(float *)(iVar7 + 0xf60) =
           (*(float *)(iVar7 + 0xf5c) - FLOAT_803e8fd4) * fVar3 * *(float *)(iVar7 + 0x1398);
      dVar9 = (double)*(float *)(iVar7 + 0xf90);
      dVar10 = (double)FLOAT_803dc074;
      dVar8 = FUN_80021434((double)(*(float *)(iVar7 + 0xf60) - *(float *)(iVar6 + 0x294)),dVar9,
                           dVar10);
      *(float *)(iVar6 + 0x294) = (float)((double)*(float *)(iVar6 + 0x294) + dVar8);
      if (*(char *)(iVar6 + 0x27a) != '\0') {
        *(undefined4 *)(iVar7 + 0xfd4) = 0;
        *(undefined4 *)(iVar7 + 0xfd8) = 0;
        *(undefined4 *)(iVar7 + 0xfe0) = 0;
        *(undefined4 *)(iVar7 + 0xfe4) = 0;
        *(undefined *)(iVar7 + 0x13fe) = 8;
        *(undefined *)(iVar7 + 0x1408) = 0;
        *(float *)(iVar6 + 0x2b8) = FLOAT_803e8ff4;
        *(float *)(iVar6 + 0x2a0) = FLOAT_803e8fec;
      }
      if ((*(short *)(iVar4 + 0xa0) == *(short *)(*(int *)(iVar7 + 0xf50) + 0x30)) ||
         (*(short *)(iVar4 + 0xa0) == *(short *)(*(int *)(iVar7 + 0xf50) + 0x32))) {
        if ((*(char *)(iVar6 + 0x346) != '\0') &&
           ((sVar5 = FUN_8002f604(iVar4), sVar5 == 0 && ((*(byte *)(iVar7 + 0x14ec) & 1) == 0)))) {
          FUN_8003042c((double)FLOAT_803e8f9c,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,
                       (int)sVar1,0,in_r6,in_r7,in_r8,in_r9,in_r10);
          *(float *)(iVar6 + 0x2a0) = FLOAT_803e8fec;
        }
      }
      else if ((*(byte *)(iVar7 + 0x14ec) & 1) == 0) {
        FUN_8003042c((double)FLOAT_803e8f9c,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,
                     (int)sVar1,0,in_r6,in_r7,in_r8,in_r9,in_r10);
        *(float *)(iVar6 + 0x2a0) = FLOAT_803e8fec;
      }
      dVar10 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,
                                                             *(uint *)(iVar7 + 0xfd4) ^ 0x80000000)
                                           - DOUBLE_803e8f78),
                            (double)(FLOAT_803e8fd0 / *(float *)(iVar7 + 0xf80)),
                            (double)FLOAT_803dc074);
      dVar8 = DOUBLE_803e8f78;
      dVar9 = (double)(FLOAT_803dc074 * *(float *)(iVar7 + 0xf84) * *(float *)(iVar7 + 0xf78));
      if (dVar10 < dVar9) {
        dVar9 = dVar10;
      }
      if (*(int *)(iVar7 + 0xfd8) < 0) {
        dVar9 = -dVar9;
      }
      *(short *)(iVar7 + 0xfd0) =
           (short)(int)((double)FLOAT_803e8fe0 * dVar9 +
                       (double)(float)((double)CONCAT44(0x43300000,
                                                        (int)*(short *)(iVar7 + 0xfd0) ^ 0x80000000)
                                      - DOUBLE_803e8f78));
      dVar9 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,
                                                            *(uint *)(iVar7 + 0xfe0) ^ 0x80000000) -
                                          dVar8),
                           (double)(FLOAT_803e8fd0 / *(float *)(iVar7 + 0xf88)),
                           (double)FLOAT_803dc074);
      dVar8 = (double)(*(float *)(iVar7 + 0xf8c) * FLOAT_803dc074);
      if (dVar9 < dVar8) {
        dVar8 = dVar9;
      }
      if (*(int *)(iVar7 + 0xfe4) < 0) {
        dVar8 = -dVar8;
      }
      *(short *)(iVar7 + 0xfdc) =
           (short)(int)((double)FLOAT_803e8fe0 * dVar8 +
                       (double)(float)((double)CONCAT44(0x43300000,
                                                        (int)*(short *)(iVar7 + 0xfdc) ^ 0x80000000)
                                      - DOUBLE_803e8f78));
      FUN_802bd180(iVar4,iVar7 + 0xb58,iVar6);
    }
  }
  else {
    FUN_80014b68(0,0x100);
    *(byte *)(iVar7 + 0x14ec) = *(byte *)(iVar7 + 0x14ec) & 0xfe | 1;
    *(undefined *)(*(int *)(iVar4 + 0x54) + 0x70) = 0;
    FUN_8003042c((double)FLOAT_803e8f9c,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,0x14,0,
                 in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar6 + 0x346) = 0;
  }
  FUN_8028688c();
  return;
}

