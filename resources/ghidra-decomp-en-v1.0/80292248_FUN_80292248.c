// Function: FUN_80292248
// Entry: 80292248
// Size: 380 bytes

void FUN_80292248(void)

{
  double dVar1;
  double dVar2;
  double dVar3;
  
  dVar1 = (double)FUN_80286048();
  if ((double)FLOAT_803e79d8 < ABS(dVar1)) {
    dVar2 = DOUBLE_803e7ab0 / ABS(dVar1);
    dVar3 = dVar2 * dVar2;
    dVar2 = (double)(float)-(dVar2 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * 
                                                  (dVar3 * (dVar3 * (dVar3 * (dVar3 * (dVar3 * (
                                                  dVar3 * (dVar3 * (DOUBLE_803e7aa8 * dVar3 +
                                                                   DOUBLE_803e7aa0) +
                                                          DOUBLE_803e7a98) + DOUBLE_803e7a90) +
                                                  DOUBLE_803e7a88) + DOUBLE_803e7a80) +
                                                  DOUBLE_803e7a78) + DOUBLE_803e7a70) +
                                                  DOUBLE_803e7a68) + DOUBLE_803e7a60) +
                                                  DOUBLE_803e7a58) + DOUBLE_803e7a50) +
                                                  DOUBLE_803e7a48) + DOUBLE_803e7a40) +
                                              DOUBLE_803e7a38) + DOUBLE_803e7a30) - DOUBLE_803e79e0)
    ;
    if (dVar1 < (double)FLOAT_803e79c4) {
      dVar2 = -dVar2;
    }
  }
  else {
    dVar2 = (double)(float)(dVar1 * dVar1);
    dVar2 = (double)(float)(dVar1 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (
                                                  dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2 * (dVar2
                                                                                               * (
                                                  dVar2 * (DOUBLE_803e7aa8 * dVar2 + DOUBLE_803e7aa0
                                                          ) + DOUBLE_803e7a98) + DOUBLE_803e7a90) +
                                                  DOUBLE_803e7a88) + DOUBLE_803e7a80) +
                                                  DOUBLE_803e7a78) + DOUBLE_803e7a70) +
                                                  DOUBLE_803e7a68) + DOUBLE_803e7a60) +
                                                  DOUBLE_803e7a58) + DOUBLE_803e7a50) +
                                                  DOUBLE_803e7a48) + DOUBLE_803e7a40) +
                                             DOUBLE_803e7a38) + DOUBLE_803e7a30));
  }
  FUN_80286094(dVar2);
  return;
}

