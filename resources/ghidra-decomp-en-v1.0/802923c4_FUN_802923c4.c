// Function: FUN_802923c4
// Entry: 802923c4
// Size: 240 bytes

void FUN_802923c4(undefined8 param_1,double param_2)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  
  dVar5 = (double)FUN_80286044();
  fVar1 = ABS((float)param_2);
  fVar2 = ABS((float)dVar5);
  if (fVar1 <= fVar2) {
    fVar1 = fVar1 / fVar2;
    dVar6 = -(double)(fVar1 * (FLOAT_803e7a0c * fVar1 * fVar1 + FLOAT_803e7a08) - FLOAT_803e79c8);
  }
  else {
    fVar2 = fVar2 / fVar1;
    dVar6 = (double)(fVar2 * (FLOAT_803e7a0c * fVar2 * fVar2 + FLOAT_803e7a08));
  }
  uVar3 = (uint)(float)dVar5 & 0x80000000;
  uVar4 = uVar3 | (uint)(float)param_2 >> 1 & 0x40000000;
  if (uVar4 != 0) {
    if (uVar3 == 0) {
      if (uVar4 == 0x40000000) {
        dVar6 = (double)(float)((double)FLOAT_803e79e8 - dVar6);
        goto LAB_80292498;
      }
    }
    else if ((int)uVar4 < -0x7fffffff) {
      dVar6 = -dVar6;
      goto LAB_80292498;
    }
    dVar6 = (double)(float)(dVar6 - (double)FLOAT_803e79e8);
  }
LAB_80292498:
  FUN_80286090(dVar6);
  return;
}

