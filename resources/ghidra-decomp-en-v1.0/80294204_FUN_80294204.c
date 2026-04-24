// Function: FUN_80294204
// Entry: 80294204
// Size: 232 bytes

void FUN_80294204(void)

{
  float fVar1;
  ushort uVar2;
  double dVar3;
  ushort local_14 [10];
  
  dVar3 = (double)FUN_80286050();
  dVar3 = (double)FUN_80292cc4((double)(float)dVar3,local_14);
  fVar1 = (float)(dVar3 * dVar3);
  uVar2 = local_14[0] & 6;
  if (uVar2 == 2) {
    dVar3 = -(double)(float)(dVar3 * (double)(fVar1 * (FLOAT_803e7d7c * fVar1 + FLOAT_803e7d78) +
                                             FLOAT_803e7d74));
  }
  else {
    if (uVar2 < 2) {
      if ((local_14[0] & 6) == 0) {
        dVar3 = (double)(fVar1 * (fVar1 * (FLOAT_803e7d8c * fVar1 + FLOAT_803e7d88) + FLOAT_803e7d84
                                 ) + FLOAT_803e7d80);
        goto LAB_802942d4;
      }
    }
    else if (uVar2 == 4) {
      dVar3 = -(double)(fVar1 * (fVar1 * (FLOAT_803e7d8c * fVar1 + FLOAT_803e7d88) + FLOAT_803e7d84)
                       + FLOAT_803e7d80);
      goto LAB_802942d4;
    }
    dVar3 = (double)(float)(dVar3 * (double)(fVar1 * (FLOAT_803e7d7c * fVar1 + FLOAT_803e7d78) +
                                            FLOAT_803e7d74));
  }
LAB_802942d4:
  FUN_8028609c(dVar3);
  return;
}

