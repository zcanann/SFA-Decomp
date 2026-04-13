// Function: FUN_802925a0
// Entry: 802925a0
// Size: 260 bytes

void FUN_802925a0(void)

{
  double dVar1;
  double dVar2;
  float afStack_34 [2];
  uint uStack_2c;
  longlong local_28;
  
  dVar1 = (double)FUN_802867b0();
  dVar2 = ABS(dVar1);
  if ((double)FLOAT_803e8638 <= dVar2) {
    if (dVar2 < (double)FLOAT_803e8644) {
      local_28 = (longlong)(int)dVar1;
      uStack_2c = (int)dVar1 ^ 0x80000000;
      afStack_34[1] = 176.0;
    }
  }
  else {
    FUN_80292444(dVar2,afStack_34);
    FUN_80292428(afStack_34);
  }
  FUN_802867fc();
  return;
}

