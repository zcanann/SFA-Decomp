// Function: FUN_80293e80
// Entry: 80293e80
// Size: 252 bytes

void FUN_80293e80(void)

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
    dVar3 = (double)(fVar1 * (fVar1 * (FLOAT_803e7d8c * fVar1 + FLOAT_803e7d88) + FLOAT_803e7d84) +
                    FLOAT_803e7d80);
  }
  else {
    if (uVar2 < 2) {
      if ((local_14[0] & 6) == 0) {
        dVar3 = (double)(float)(dVar4 * (double)(fVar1 * (FLOAT_803e7d7c * fVar1 + FLOAT_803e7d78) +
                                                FLOAT_803e7d74));
        goto LAB_80293f64;
      }
    }
    else if (uVar2 == 4) {
      dVar3 = -(double)(float)(dVar4 * (double)(fVar1 * (FLOAT_803e7d7c * fVar1 + FLOAT_803e7d78) +
                                               FLOAT_803e7d74));
      goto LAB_80293f64;
    }
    dVar3 = -(double)(fVar1 * (fVar1 * (FLOAT_803e7d8c * fVar1 + FLOAT_803e7d88) + FLOAT_803e7d84) +
                     FLOAT_803e7d80);
  }
LAB_80293f64:
  FUN_8028609c(dVar3);
  return;
}

