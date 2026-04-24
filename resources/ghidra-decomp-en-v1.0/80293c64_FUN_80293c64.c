// Function: FUN_80293c64
// Entry: 80293c64
// Size: 320 bytes

void FUN_80293c64(void)

{
  float fVar1;
  float fVar2;
  ushort uVar3;
  float *pfVar4;
  float *pfVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  undefined8 uVar8;
  ushort local_34 [2];
  
  uVar8 = FUN_80286044();
  pfVar4 = (float *)((ulonglong)uVar8 >> 0x20);
  pfVar5 = (float *)uVar8;
  dVar7 = extraout_f1;
  dVar6 = (double)FUN_80292cc4(extraout_f1,local_34);
  fVar1 = (float)(dVar6 * dVar6);
  fVar2 = (float)(dVar6 * (double)(fVar1 * (FLOAT_803e7d4c * fVar1 + FLOAT_803e7d48) +
                                  FLOAT_803e7d44));
  fVar1 = fVar1 * (fVar1 * (FLOAT_803e7d5c * fVar1 + FLOAT_803e7d58) + FLOAT_803e7d54) +
          FLOAT_803e7d50;
  uVar3 = local_34[0] & 6;
  if (uVar3 == 2) {
    if (dVar7 < (double)FLOAT_803e7d40) {
      fVar1 = -fVar1;
    }
    *pfVar4 = fVar1;
    *pfVar5 = -fVar2;
  }
  else {
    if (uVar3 < 2) {
      if ((local_34[0] & 6) == 0) {
        if (dVar7 < (double)FLOAT_803e7d40) {
          fVar2 = -fVar2;
        }
        *pfVar4 = fVar2;
        *pfVar5 = fVar1;
        goto LAB_80293d88;
      }
    }
    else if (uVar3 == 4) {
      if ((double)FLOAT_803e7d40 <= dVar7) {
        fVar2 = -fVar2;
      }
      *pfVar4 = fVar2;
      *pfVar5 = -fVar1;
      goto LAB_80293d88;
    }
    if ((double)FLOAT_803e7d40 <= dVar7) {
      fVar1 = -fVar1;
    }
    *pfVar4 = fVar1;
    *pfVar5 = fVar2;
  }
LAB_80293d88:
  FUN_80286090();
  return;
}

