// Function: FUN_80016c18
// Entry: 80016c18
// Size: 48 bytes

void FUN_80016c18(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc9c8;
  iVar1 = DAT_803dc9c8 * 5;
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar1] = 1;
  (&DAT_8033a544)[iVar2 * 5] = param_1;
  (&DAT_8033a548)[iVar2 * 5] = param_2;
  return;
}

