// Function: FUN_802925c4
// Entry: 802925c4
// Size: 480 bytes

void FUN_802925c4(undefined8 param_1,double param_2)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  dVar5 = (double)FUN_80286044();
  fVar1 = ABS((float)param_2);
  fVar2 = ABS((float)dVar5);
  if (fVar1 < fVar2) {
    dVar6 = (double)(fVar1 / fVar2);
    dVar7 = dVar6 * dVar6;
    dVar6 = -(dVar6 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7
                                                                                               * (
                                                  dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (
                                                  DOUBLE_803e7aa8 * dVar7 + DOUBLE_803e7aa0) +
                                                  DOUBLE_803e7a98) + DOUBLE_803e7a90) +
                                                  DOUBLE_803e7a88) + DOUBLE_803e7a80) +
                                                  DOUBLE_803e7a78) + DOUBLE_803e7a70) +
                                                  DOUBLE_803e7a68) + DOUBLE_803e7a60) +
                                                  DOUBLE_803e7a58) + DOUBLE_803e7a50) +
                                                 DOUBLE_803e7a48) + DOUBLE_803e7a40) +
                               DOUBLE_803e7a38) + DOUBLE_803e7a30) - DOUBLE_803e79e0);
  }
  else {
    dVar6 = (double)(fVar2 / fVar1);
    dVar7 = dVar6 * dVar6;
    dVar6 = dVar6 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (dVar7 *
                                                                                             (dVar7 
                                                  * (dVar7 * (dVar7 * (dVar7 * (dVar7 * (
                                                  DOUBLE_803e7aa8 * dVar7 + DOUBLE_803e7aa0) +
                                                  DOUBLE_803e7a98) + DOUBLE_803e7a90) +
                                                  DOUBLE_803e7a88) + DOUBLE_803e7a80) +
                                                  DOUBLE_803e7a78) + DOUBLE_803e7a70) +
                                                  DOUBLE_803e7a68) + DOUBLE_803e7a60) +
                                                  DOUBLE_803e7a58) + DOUBLE_803e7a50) +
                                               DOUBLE_803e7a48) + DOUBLE_803e7a40) + DOUBLE_803e7a38
                             ) + DOUBLE_803e7a30);
  }
  uVar3 = (uint)(float)dVar5 & 0x80000000;
  uVar4 = uVar3 | (uint)(float)param_2 >> 1 & 0x40000000;
  if (uVar4 == 0) {
    dVar5 = (double)(float)dVar6;
  }
  else {
    if (uVar3 == 0) {
      if (uVar4 == 0x40000000) {
        dVar5 = (double)(float)(DOUBLE_803e7a00 - dVar6);
        goto LAB_80292788;
      }
    }
    else if ((int)uVar4 < -0x7fffffff) {
      dVar5 = (double)(float)-dVar6;
      goto LAB_80292788;
    }
    dVar5 = (double)(float)(dVar6 - DOUBLE_803e7a00);
  }
LAB_80292788:
  FUN_80286090(dVar5);
  return;
}

