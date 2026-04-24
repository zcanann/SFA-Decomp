// Function: FUN_80293234
// Entry: 80293234
// Size: 264 bytes

void FUN_80293234(void)

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
LAB_802932dc:
        dVar3 = (double)(fVar1 * (FLOAT_803e7c88 * fVar1 + FLOAT_803e7c84) + FLOAT_803e7c80);
      }
      else {
        if (uVar2 < 0x2000) {
          if (uVar2 == 0) goto LAB_802932c8;
        }
        else if (uVar2 == 0x4000) goto LAB_802932dc;
LAB_8029330c:
        dVar3 = -(double)(fVar1 * (FLOAT_803e7c88 * fVar1 + FLOAT_803e7c84) + FLOAT_803e7c80);
      }
      goto LAB_80293320;
    }
    if (uVar2 == 0xe000) {
LAB_802932c8:
      dVar3 = (double)(float)(dVar3 * (double)(FLOAT_803e7c90 * fVar1 + FLOAT_803e7c8c));
      goto LAB_80293320;
    }
    if ((0xdfff < uVar2) || (uVar2 != 0x8000)) goto LAB_8029330c;
  }
  dVar3 = -(double)(float)(dVar3 * (double)(FLOAT_803e7c90 * fVar1 + FLOAT_803e7c8c));
LAB_80293320:
  FUN_8028609c(dVar3);
  return;
}

