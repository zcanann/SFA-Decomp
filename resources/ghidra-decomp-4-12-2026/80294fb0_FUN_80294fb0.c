// Function: FUN_80294fb0
// Entry: 80294fb0
// Size: 404 bytes

double FUN_80294fb0(double param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  undefined8 local_18;
  
  fVar1 = (float)param_1;
  if (((uint)fVar1 & 0x80000000) == 0) {
    fVar2 = FLOAT_803e8ad4 + FLOAT_803e8ad0 * fVar1;
  }
  else {
    fVar2 = FLOAT_803e8ad0 * fVar1 - FLOAT_803e8ad4;
  }
  uVar4 = (uint)fVar2;
  uVar3 = uVar4 & 3;
  local_18 = (double)CONCAT44(0x43300000,uVar4 << 1 ^ 0x80000000);
  dVar6 = (double)(DAT_80333684 * fVar1 +
                  DAT_80333680 * fVar1 +
                  DAT_8033367c * fVar1 +
                  DAT_80333678 * fVar1 + (fVar1 - (float)(local_18 - DOUBLE_803e8ae0)));
  dVar5 = FUN_80294e7c(dVar6);
  if ((double)FLOAT_803e8ad8 <= dVar5) {
    fVar1 = (float)(dVar6 * dVar6);
    if ((uVar4 & 1) == 0) {
      dVar5 = (double)((fVar1 * (fVar1 * (fVar1 * (DAT_803338ac * fVar1 + DAT_803338b4) +
                                         DAT_803338bc) + DAT_803338c4) + DAT_803338cc) *
                      *(float *)(&DAT_80333890 + uVar3 * 8));
    }
    else {
      dVar5 = (double)((float)(dVar6 * -(double)(fVar1 * (fVar1 * (fVar1 * (DAT_803338b0 * fVar1 +
                                                                           DAT_803338b8) +
                                                                  DAT_803338c0) + DAT_803338c8) +
                                                DAT_803338d0)) *
                      *(float *)(&DAT_8033388c + uVar3 * 8));
    }
  }
  else {
    dVar5 = -(double)(float)(dVar6 * (double)*(float *)(&DAT_8033388c + uVar3 * 8) -
                            (double)*(float *)(&DAT_80333890 + uVar3 * 8));
  }
  return dVar5;
}

