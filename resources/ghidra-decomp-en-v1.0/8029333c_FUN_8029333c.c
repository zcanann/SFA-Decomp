// Function: FUN_8029333c
// Entry: 8029333c
// Size: 296 bytes

void FUN_8029333c(void)

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
LAB_802933ec:
        dVar3 = (double)(fVar1 * (fVar1 * (FLOAT_803e7cac * fVar1 + FLOAT_803e7ca8) + FLOAT_803e7ca4
                                 ) + FLOAT_803e7ca0);
      }
      else {
        if (uVar2 < 0x2000) {
          if (uVar2 == 0) goto LAB_802933d0;
        }
        else if (uVar2 == 0x4000) goto LAB_802933ec;
LAB_8029342c:
        dVar3 = -(double)(fVar1 * (fVar1 * (FLOAT_803e7cac * fVar1 + FLOAT_803e7ca8) +
                                  FLOAT_803e7ca4) + FLOAT_803e7ca0);
      }
      goto LAB_80293448;
    }
    if (uVar2 == 0xe000) {
LAB_802933d0:
      dVar3 = (double)(float)(dVar3 * (double)(fVar1 * (FLOAT_803e7c9c * fVar1 + FLOAT_803e7c98) +
                                              FLOAT_803e7c94));
      goto LAB_80293448;
    }
    if ((0xdfff < uVar2) || (uVar2 != 0x8000)) goto LAB_8029342c;
  }
  dVar3 = -(double)(float)(dVar3 * (double)(fVar1 * (FLOAT_803e7c9c * fVar1 + FLOAT_803e7c98) +
                                           FLOAT_803e7c94));
LAB_80293448:
  FUN_8028609c(dVar3);
  return;
}

