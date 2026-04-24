// Function: FUN_80292194
// Entry: 80292194
// Size: 180 bytes

void FUN_80292194(void)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar1 = (double)FUN_8028603c();
  if ((double)FLOAT_803e79d8 < ABS(dVar1)) {
    dVar2 = (double)FUN_80292dec(ABS(dVar1));
    dVar4 = (double)((float)(dVar2 * dVar2) *
                     (FLOAT_803e7a18 * (float)(dVar2 * dVar2) + FLOAT_803e7a14) + FLOAT_803e7a10);
    dVar3 = (double)(float)(dVar2 * dVar4 - (double)FLOAT_803e79c8);
    if ((double)FLOAT_803e79c4 <= dVar1) {
      dVar3 = -(double)(float)(dVar2 * dVar4 - (double)FLOAT_803e79c8);
    }
  }
  else {
    dVar3 = (double)(float)(dVar1 * (double)((float)(dVar1 * dVar1) *
                                             (FLOAT_803e7a18 * (float)(dVar1 * dVar1) +
                                             FLOAT_803e7a14) + FLOAT_803e7a10));
  }
  FUN_80286088(dVar3);
  return;
}

