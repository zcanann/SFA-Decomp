// Function: FUN_80036d04
// Entry: 80036d04
// Size: 116 bytes

uint FUN_80036d04(int param_1,int param_2)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  
  if ((-1 < param_2) && (param_2 < 0x54)) {
    uVar2 = (uint)(byte)(&DAT_80343958)[param_2];
    uVar3 = (uint)(byte)(&DAT_80343959)[param_2];
    for (piVar1 = &DAT_80343558 + uVar2; ((int)uVar2 < (int)uVar3 && (param_1 != *piVar1));
        piVar1 = piVar1 + 1) {
      uVar2 = uVar2 + 1;
    }
    return ((int)(uVar3 ^ uVar2) >> 1) - ((uVar3 ^ uVar2) & uVar3) >> 0x1f;
  }
  return 0;
}

