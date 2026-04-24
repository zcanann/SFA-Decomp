// Function: FUN_8029454c
// Entry: 8029454c
// Size: 148 bytes

void FUN_8029454c(void)

{
  float fVar1;
  double dVar2;
  double dVar3;
  ushort local_24 [18];
  
  dVar2 = (double)FUN_80286048();
  dVar3 = (double)FUN_80292cc4(dVar2,local_24);
  fVar1 = (float)(dVar3 * dVar3);
  dVar3 = (double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (FLOAT_803e7e2c * fVar1 + FLOAT_803e7e28
                                                            ) + FLOAT_803e7e24) + FLOAT_803e7e20));
  if ((local_24[0] & 2) != 0) {
    dVar3 = (double)(float)((double)FLOAT_803e7e18 / dVar3);
  }
  if (dVar2 < (double)FLOAT_803e7e1c) {
    dVar3 = -dVar3;
  }
  FUN_80286094(dVar3);
  return;
}

