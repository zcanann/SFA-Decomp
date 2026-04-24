// Function: FUN_80293da4
// Entry: 80293da4
// Size: 220 bytes

void FUN_80293da4(void)

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
    dVar3 = (double)(fVar1 * (FLOAT_803e7d70 * fVar1 + FLOAT_803e7d6c) + FLOAT_803e7d68);
  }
  else {
    if (uVar2 < 2) {
      if ((local_14[0] & 6) == 0) {
        dVar3 = (double)(float)(dVar4 * (double)(FLOAT_803e7d64 * fVar1 + FLOAT_803e7d60));
        goto LAB_80293e68;
      }
    }
    else if (uVar2 == 4) {
      dVar3 = -(double)(float)(dVar4 * (double)(FLOAT_803e7d64 * fVar1 + FLOAT_803e7d60));
      goto LAB_80293e68;
    }
    dVar3 = -(double)(fVar1 * (FLOAT_803e7d70 * fVar1 + FLOAT_803e7d6c) + FLOAT_803e7d68);
  }
LAB_80293e68:
  FUN_8028609c(dVar3);
  return;
}

