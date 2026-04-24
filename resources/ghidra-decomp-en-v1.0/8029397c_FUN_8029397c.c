// Function: FUN_8029397c
// Entry: 8029397c
// Size: 328 bytes

void FUN_8029397c(void)

{
  float fVar1;
  uint uVar2;
  double dVar3;
  undefined2 local_1e [5];
  
  uVar2 = FUN_80286050();
  local_1e[0] = (undefined2)(uVar2 << 2);
  dVar3 = (double)FUN_80291e08(local_1e);
  fVar1 = (float)(dVar3 * dVar3);
  uVar2 = uVar2 & 0xe000;
  if (uVar2 != 0x6000) {
    if (uVar2 < 0x6000) {
      if (uVar2 == 0x2000) {
LAB_80293a38:
        dVar3 = -(double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (FLOAT_803e7cbc * fVar1 +
                                                                   FLOAT_803e7cb8) + FLOAT_803e7cb4)
                                                 + FLOAT_803e7cb0));
      }
      else {
        if (uVar2 < 0x2000) {
          if (uVar2 == 0) goto LAB_80293a10;
        }
        else if (uVar2 == 0x4000) goto LAB_80293a38;
LAB_80293a88:
        dVar3 = (double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (FLOAT_803e7cbc * fVar1 +
                                                                  FLOAT_803e7cb8) + FLOAT_803e7cb4)
                                                + FLOAT_803e7cb0));
      }
      goto LAB_80293aa8;
    }
    if (uVar2 == 0xe000) {
LAB_80293a10:
      dVar3 = (double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7ccc * fVar1 + FLOAT_803e7cc8) +
                                        FLOAT_803e7cc4) + FLOAT_803e7cc0) + FLOAT_803e7ca0);
      goto LAB_80293aa8;
    }
    if ((0xdfff < uVar2) || (uVar2 != 0x8000)) goto LAB_80293a88;
  }
  dVar3 = -(double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7ccc * fVar1 + FLOAT_803e7cc8) +
                                     FLOAT_803e7cc4) + FLOAT_803e7cc0) + FLOAT_803e7ca0);
LAB_80293aa8:
  FUN_8028609c(dVar3);
  return;
}

