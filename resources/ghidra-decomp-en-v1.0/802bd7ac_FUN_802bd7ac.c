// Function: FUN_802bd7ac
// Entry: 802bd7ac
// Size: 1056 bytes

void FUN_802bd7ac(void)

{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860dc();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  iVar8 = *(int *)(iVar4 + 0xb8);
  if (*(char *)(iVar7 + 0x27a) != '\0') {
    *(float *)(iVar7 + 0x294) = FLOAT_803e8304;
  }
  dVar10 = (double)FUN_80021370((double)*(float *)(iVar7 + 0x280),(double)*(float *)(iVar8 + 0x1384)
                                ,(double)FLOAT_803db414);
  *(float *)(iVar7 + 0x280) = (float)((double)*(float *)(iVar7 + 0x280) - dVar10);
  if (*(float *)(iVar7 + 0x280) <= DAT_80335284) {
    *(float *)(iVar7 + 0x280) = FLOAT_803e8304;
  }
  fVar2 = FLOAT_803e8304;
  *(float *)(iVar7 + 0x284) = FLOAT_803e8304;
  *(float *)(iVar4 + 0x24) = fVar2;
  *(float *)(iVar4 + 0x2c) = fVar2;
  if (((((char)*(byte *)(iVar8 + 0xf48) < '\0') || ((*(byte *)(iVar8 + 0xf48) >> 6 & 1) != 0)) ||
      ((*(byte *)(iVar8 + 0x14ec) & 1) != 0)) || ((*(uint *)(iVar7 + 0x31c) & 0x100) == 0)) {
    if (((*(float *)(iVar7 + 0x29c) < FLOAT_803e8358) ||
        (*(float *)(iVar7 + 0x298) < FLOAT_803e8358)) ||
       (*(float *)(iVar7 + 0x294) < *(float *)(*(int *)(iVar8 + 0xf58) + 4))) {
      sVar1 = **(short **)(iVar8 + 0xf50);
      *(undefined2 *)(iVar7 + 0x278) = 0;
      *(float *)(iVar8 + 0xf5c) = FLOAT_803e82e8;
      fVar2 = (*(float *)(iVar7 + 0x298) - FLOAT_803e8308) / FLOAT_803e82fc;
      fVar3 = FLOAT_803e8304;
      if ((FLOAT_803e8304 <= fVar2) && (fVar3 = fVar2, FLOAT_803e8338 < fVar2)) {
        fVar3 = FLOAT_803e8338;
      }
      *(float *)(iVar8 + 0xf60) =
           (*(float *)(iVar8 + 0xf5c) - FLOAT_803e833c) * fVar3 * *(float *)(iVar8 + 0x1398);
      dVar10 = (double)FUN_80021370((double)(*(float *)(iVar8 + 0xf60) - *(float *)(iVar7 + 0x294)),
                                    (double)*(float *)(iVar8 + 0xf90),(double)FLOAT_803db414);
      *(float *)(iVar7 + 0x294) = (float)((double)*(float *)(iVar7 + 0x294) + dVar10);
      if (*(char *)(iVar7 + 0x27a) != '\0') {
        *(undefined4 *)(iVar8 + 0xfd4) = 0;
        *(undefined4 *)(iVar8 + 0xfd8) = 0;
        *(undefined4 *)(iVar8 + 0xfe0) = 0;
        *(undefined4 *)(iVar8 + 0xfe4) = 0;
        *(undefined *)(iVar8 + 0x13fe) = 8;
        *(undefined *)(iVar8 + 0x1408) = 0;
        *(float *)(iVar7 + 0x2b8) = FLOAT_803e835c;
        *(float *)(iVar7 + 0x2a0) = FLOAT_803e8354;
      }
      if ((*(short *)(iVar4 + 0xa0) == *(short *)(*(int *)(iVar8 + 0xf50) + 0x30)) ||
         (*(short *)(iVar4 + 0xa0) == *(short *)(*(int *)(iVar8 + 0xf50) + 0x32))) {
        if ((*(char *)(iVar7 + 0x346) != '\0') &&
           ((iVar6 = FUN_8002f50c(iVar4), iVar6 == 0 && ((*(byte *)(iVar8 + 0x14ec) & 1) == 0)))) {
          FUN_80030334((double)FLOAT_803e8304,iVar4,(int)sVar1,0);
          *(float *)(iVar7 + 0x2a0) = FLOAT_803e8354;
        }
      }
      else if ((*(byte *)(iVar8 + 0x14ec) & 1) == 0) {
        FUN_80030334((double)FLOAT_803e8304,iVar4,(int)sVar1,0);
        *(float *)(iVar7 + 0x2a0) = FLOAT_803e8354;
      }
      dVar11 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,
                                                                     *(uint *)(iVar8 + 0xfd4) ^
                                                                     0x80000000) - DOUBLE_803e82e0),
                                    (double)(FLOAT_803e8338 / *(float *)(iVar8 + 0xf80)),
                                    (double)FLOAT_803db414);
      dVar10 = DOUBLE_803e82e0;
      dVar9 = (double)(FLOAT_803db414 * *(float *)(iVar8 + 0xf84) * *(float *)(iVar8 + 0xf78));
      if (dVar11 < dVar9) {
        dVar9 = dVar11;
      }
      if (*(int *)(iVar8 + 0xfd8) < 0) {
        dVar9 = -dVar9;
      }
      *(short *)(iVar8 + 0xfd0) =
           (short)(int)((double)FLOAT_803e8348 * dVar9 +
                       (double)(float)((double)CONCAT44(0x43300000,
                                                        (int)*(short *)(iVar8 + 0xfd0) ^ 0x80000000)
                                      - DOUBLE_803e82e0));
      dVar9 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,
                                                                    *(uint *)(iVar8 + 0xfe0) ^
                                                                    0x80000000) - dVar10),
                                   (double)(FLOAT_803e8338 / *(float *)(iVar8 + 0xf88)),
                                   (double)FLOAT_803db414);
      dVar10 = (double)(*(float *)(iVar8 + 0xf8c) * FLOAT_803db414);
      if (dVar9 < dVar10) {
        dVar10 = dVar9;
      }
      if (*(int *)(iVar8 + 0xfe4) < 0) {
        dVar10 = -dVar10;
      }
      *(short *)(iVar8 + 0xfdc) =
           (short)(int)((double)FLOAT_803e8348 * dVar10 +
                       (double)(float)((double)CONCAT44(0x43300000,
                                                        (int)*(short *)(iVar8 + 0xfdc) ^ 0x80000000)
                                      - DOUBLE_803e82e0));
      FUN_802bca10(iVar4,iVar8 + 0xb58,iVar7);
      uVar5 = 0;
    }
    else {
      uVar5 = 3;
    }
  }
  else {
    FUN_80014b3c(0,0x100);
    *(byte *)(iVar8 + 0x14ec) = *(byte *)(iVar8 + 0x14ec) & 0xfe | 1;
    *(undefined *)(*(int *)(iVar4 + 0x54) + 0x70) = 0;
    FUN_80030334((double)FLOAT_803e8304,iVar4,0x14,0);
    *(undefined *)(iVar7 + 0x346) = 0;
    uVar5 = 3;
  }
  FUN_80286128(uVar5);
  return;
}

