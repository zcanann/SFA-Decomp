// Function: FUN_800173e4
// Entry: 800173e4
// Size: 80 bytes

void FUN_800173e4(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc9c8;
  iVar1 = DAT_803dc9c8 * 5;
  if (param_1 == 0xff) {
    DAT_803dc9cc = (undefined *)0x0;
  }
  else {
    DAT_803dc9cc = &DAT_802c7400 + param_1 * 0x20;
  }
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar1] = 8;
  (&DAT_8033a544)[iVar2 * 5] = param_1;
  return;
}

