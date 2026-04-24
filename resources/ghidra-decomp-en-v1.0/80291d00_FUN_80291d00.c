// Function: FUN_80291d00
// Entry: 80291d00
// Size: 216 bytes

void FUN_80291d00(void)

{
  float fVar1;
  double dVar2;
  double dVar3;
  float local_24;
  short local_20 [16];
  
  dVar2 = (double)FUN_8028604c();
  fVar1 = FLOAT_803e797c;
  if ((double)FLOAT_803e7978 <= dVar2) {
    FUN_80291e24(dVar2,local_20);
    dVar3 = (double)FUN_80291e08(local_20);
    fVar1 = (float)(dVar2 - dVar3);
    if (fVar1 == FLOAT_803e797c) {
      local_24 = FLOAT_803e7980;
    }
    else {
      if (dVar2 < (double)FLOAT_803e797c) {
        local_20[0] = local_20[0] + -1;
        fVar1 = fVar1 + FLOAT_803e7980;
      }
      local_24 = fVar1 * (fVar1 * (fVar1 * (FLOAT_803e7994 * fVar1 + FLOAT_803e7990) +
                                  FLOAT_803e798c) + FLOAT_803e7988) + FLOAT_803e7984;
    }
    fVar1 = (float)((int)local_24 + local_20[0] * 0x800000);
  }
  FUN_80286098((double)fVar1);
  return;
}

