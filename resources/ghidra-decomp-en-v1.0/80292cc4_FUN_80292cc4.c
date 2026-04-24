// Function: FUN_80292cc4
// Entry: 80292cc4
// Size: 120 bytes

void FUN_80292cc4(void)

{
  ushort *puVar1;
  double extraout_f1;
  double dVar2;
  double dVar3;
  
  puVar1 = (ushort *)FUN_80286050();
  dVar3 = (double)(FLOAT_803e7bf8 * ABS((float)extraout_f1));
  FUN_80291ce4(dVar3,puVar1);
  *puVar1 = *puVar1 + 1 & 0xfffe;
  dVar2 = (double)FUN_80291cc8(puVar1);
  FUN_8028609c((double)(float)(dVar3 - dVar2));
  return;
}

