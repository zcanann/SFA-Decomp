// Function: FUN_80293f7c
// Entry: 80293f7c
// Size: 284 bytes

void FUN_80293f7c(void)

{
  float fVar1;
  ushort uVar2;
  double dVar3;
  double dVar4;
  ushort local_14 [10];
  
  dVar3 = (double)FUN_80286050();
  dVar4 = (double)FUN_80292cc4((double)(float)dVar3,local_14);
  local_14[0] = local_14[0] + ((ushort)((uint)(float)dVar3 >> 0x1d) & 4);
  fVar1 = (float)(dVar4 * dVar4);
  uVar2 = local_14[0] & 6;
  if (uVar2 == 2) {
    dVar3 = (double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7dac * fVar1 + FLOAT_803e7da8) +
                                      FLOAT_803e7da4) + FLOAT_803e7da0) + FLOAT_803e7d80);
  }
  else {
    if (uVar2 < 2) {
      if ((local_14[0] & 6) == 0) {
        dVar3 = (double)(float)(dVar4 * (double)(fVar1 * (fVar1 * (FLOAT_803e7d9c * fVar1 +
                                                                  FLOAT_803e7d98) + FLOAT_803e7d94)
                                                + FLOAT_803e7d90));
        goto LAB_80294080;
      }
    }
    else if (uVar2 == 4) {
      dVar3 = -(double)(float)(dVar4 * (double)(fVar1 * (fVar1 * (FLOAT_803e7d9c * fVar1 +
                                                                 FLOAT_803e7d98) + FLOAT_803e7d94) +
                                               FLOAT_803e7d90));
      goto LAB_80294080;
    }
    dVar3 = -(double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7dac * fVar1 + FLOAT_803e7da8) +
                                       FLOAT_803e7da4) + FLOAT_803e7da0) + FLOAT_803e7d80);
  }
LAB_80294080:
  FUN_8028609c(dVar3);
  return;
}

