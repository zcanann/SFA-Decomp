// Function: FUN_802942ec
// Entry: 802942ec
// Size: 264 bytes

void FUN_802942ec(void)

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
    dVar3 = -(double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (FLOAT_803e7d9c * fVar1 +
                                                               FLOAT_803e7d98) + FLOAT_803e7d94) +
                                             FLOAT_803e7d90));
  }
  else {
    if (uVar2 < 2) {
      if ((local_14[0] & 6) == 0) {
        dVar3 = (double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7dac * fVar1 + FLOAT_803e7da8) +
                                          FLOAT_803e7da4) + FLOAT_803e7da0) + FLOAT_803e7d80);
        goto LAB_802943dc;
      }
    }
    else if (uVar2 == 4) {
      dVar3 = -(double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7dac * fVar1 + FLOAT_803e7da8) +
                                         FLOAT_803e7da4) + FLOAT_803e7da0) + FLOAT_803e7d80);
      goto LAB_802943dc;
    }
    dVar3 = (double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (FLOAT_803e7d9c * fVar1 +
                                                              FLOAT_803e7d98) + FLOAT_803e7d94) +
                                            FLOAT_803e7d90));
  }
LAB_802943dc:
  FUN_8028609c(dVar3);
  return;
}

