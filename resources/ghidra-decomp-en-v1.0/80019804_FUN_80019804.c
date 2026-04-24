// Function: FUN_80019804
// Entry: 80019804
// Size: 72 bytes

void FUN_80019804(uint param_1)

{
  int iVar1;
  
  if ((param_1 & 1) != 0) {
    DAT_803dc9aa = 0;
    DAT_803dc9a8 = 0;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  iVar1 = DAT_803dc9c8 * 5;
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar1] = 0xb;
  return;
}

