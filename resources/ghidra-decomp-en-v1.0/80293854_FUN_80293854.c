// Function: FUN_80293854
// Entry: 80293854
// Size: 296 bytes

void FUN_80293854(void)

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
LAB_80293908:
        dVar3 = -(double)(float)(dVar3 * (double)(fVar1 * (FLOAT_803e7c9c * fVar1 + FLOAT_803e7c98)
                                                 + FLOAT_803e7c94));
      }
      else {
        if (uVar2 < 0x2000) {
          if (uVar2 == 0) goto LAB_802938e8;
        }
        else if (uVar2 == 0x4000) goto LAB_80293908;
LAB_80293948:
        dVar3 = (double)(float)(dVar3 * (double)(fVar1 * (FLOAT_803e7c9c * fVar1 + FLOAT_803e7c98) +
                                                FLOAT_803e7c94));
      }
      goto LAB_80293960;
    }
    if (uVar2 == 0xe000) {
LAB_802938e8:
      dVar3 = (double)(fVar1 * (fVar1 * (FLOAT_803e7cac * fVar1 + FLOAT_803e7ca8) + FLOAT_803e7ca4)
                      + FLOAT_803e7ca0);
      goto LAB_80293960;
    }
    if ((0xdfff < uVar2) || (uVar2 != 0x8000)) goto LAB_80293948;
  }
  dVar3 = -(double)(fVar1 * (fVar1 * (FLOAT_803e7cac * fVar1 + FLOAT_803e7ca8) + FLOAT_803e7ca4) +
                   FLOAT_803e7ca0);
LAB_80293960:
  FUN_8028609c(dVar3);
  return;
}

