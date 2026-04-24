// Function: FUN_80036c0c
// Entry: 80036c0c
// Size: 116 bytes

uint FUN_80036c0c(int param_1,int param_2)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  
  if ((-1 < param_2) && (param_2 < 0x54)) {
    uVar2 = (uint)(byte)(&DAT_80342cf8)[param_2];
    uVar3 = (uint)(byte)(&DAT_80342cf9)[param_2];
    for (piVar1 = &DAT_803428f8 + uVar2; ((int)uVar2 < (int)uVar3 && (param_1 != *piVar1));
        piVar1 = piVar1 + 1) {
      uVar2 = uVar2 + 1;
    }
    return ((int)(uVar3 ^ uVar2) >> 1) - ((uVar3 ^ uVar2) & uVar3) >> 0x1f;
  }
  return 0;
}

