// Function: FUN_80291f44
// Entry: 80291f44
// Size: 176 bytes

void FUN_80291f44(void)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar2 = (double)FUN_80286044();
  if ((double)FLOAT_803e79c0 < ABS(dVar2)) {
    dVar4 = -(double)(float)((double)FLOAT_803e79c0 * ABS(dVar2) - (double)FLOAT_803e79c0);
    dVar3 = (double)FUN_8029312c(dVar4);
    fVar1 = (float)(dVar3 * (double)(float)((double)FLOAT_803e79d4 * dVar4 + (double)FLOAT_803e79d0)
                   );
    if (dVar2 < (double)FLOAT_803e79c4) {
      dVar2 = (double)(FLOAT_803e79cc * fVar1 - FLOAT_803e79c8);
    }
    else {
      dVar2 = -(double)(FLOAT_803e79cc * fVar1 - FLOAT_803e79c8);
    }
  }
  else {
    dVar2 = (double)(float)(dVar2 * (double)(FLOAT_803e79d4 * (float)(dVar2 * dVar2) +
                                            FLOAT_803e79d0));
  }
  FUN_80286090(dVar2);
  return;
}

