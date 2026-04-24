// Function: FUN_802920a4
// Entry: 802920a4
// Size: 240 bytes

void FUN_802920a4(void)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar2 = (double)FUN_80286044();
  if ((double)FLOAT_803e79c0 < ABS(dVar2)) {
    dVar4 = -(double)(float)((double)FLOAT_803e79c0 * ABS(dVar2) - (double)FLOAT_803e79c0);
    dVar3 = (double)FUN_8029312c(dVar4);
    fVar1 = (float)(dVar3 * (double)(float)(dVar4 * (double)(float)(dVar4 * (double)(float)(dVar4 * 
                                                  (double)(float)(dVar4 * (double)(float)((double)
                                                  FLOAT_803e79fc * dVar4 + (double)FLOAT_803e79f8) +
                                                  (double)FLOAT_803e79f4) + (double)FLOAT_803e79f0)
                                                  + (double)FLOAT_803e79ec) + (double)FLOAT_803e79d8
                                           ));
    if (dVar2 < (double)FLOAT_803e79c4) {
      dVar2 = -(double)(FLOAT_803e79cc * fVar1 - FLOAT_803e79e8);
    }
    else {
      dVar2 = (double)(FLOAT_803e79cc * fVar1);
    }
  }
  else {
    fVar1 = (float)(dVar2 * dVar2);
    dVar2 = -(double)(float)(dVar2 * (double)(fVar1 * (fVar1 * (fVar1 * (fVar1 * (FLOAT_803e79fc *
                                                                                  fVar1 + 
                                                  FLOAT_803e79f8) + FLOAT_803e79f4) + FLOAT_803e79f0
                                                  ) + FLOAT_803e79ec) + FLOAT_803e79d8) -
                            (double)FLOAT_803e79c8);
  }
  FUN_80286090(dVar2);
  return;
}

