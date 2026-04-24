// Function: FUN_80293464
// Entry: 80293464
// Size: 328 bytes

void FUN_80293464(void)

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
LAB_8029351c:
        dVar3 = (double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7ccc * fVar1 + FLOAT_803e7cc8) +
                                          FLOAT_803e7cc4) + FLOAT_803e7cc0) + FLOAT_803e7ca0);
      }
      else {
        if (uVar2 < 0x2000) {
          if (uVar2 == 0) goto LAB_802934f8;
        }
        else if (uVar2 == 0x4000) goto LAB_8029351c;
LAB_8029356c:
        dVar3 = -(double)(fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7ccc * fVar1 + FLOAT_803e7cc8) +
                                           FLOAT_803e7cc4) + FLOAT_803e7cc0) + FLOAT_803e7ca0);
      }
      goto LAB_80293590;
    }
    if (uVar2 == 0xe000) {
LAB_802934f8:
      dVar3 = (double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (FLOAT_803e7cbc * fVar1 +
                                                                FLOAT_803e7cb8) + FLOAT_803e7cb4) +
                                              FLOAT_803e7cb0));
      goto LAB_80293590;
    }
    if ((0xdfff < uVar2) || (uVar2 != 0x8000)) goto LAB_8029356c;
  }
  dVar3 = -(double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (FLOAT_803e7cbc * fVar1 +
                                                             FLOAT_803e7cb8) + FLOAT_803e7cb4) +
                                           FLOAT_803e7cb0));
LAB_80293590:
  FUN_8028609c(dVar3);
  return;
}

