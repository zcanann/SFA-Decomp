// Function: FUN_80292460
// Entry: 80292460
// Size: 216 bytes

void FUN_80292460(void)

{
  double dVar1;
  double dVar2;
  short local_20 [16];
  
  dVar1 = (double)FUN_802867b0();
  if ((double)FLOAT_803e8610 <= dVar1) {
    FUN_80292584(dVar1,(float *)local_20);
    dVar2 = FUN_80292568((float *)local_20);
    if (((float)(dVar1 - dVar2) != FLOAT_803e8614) && (dVar1 < (double)FLOAT_803e8614)) {
      local_20[0] = local_20[0] + -1;
    }
  }
  FUN_802867fc();
  return;
}

