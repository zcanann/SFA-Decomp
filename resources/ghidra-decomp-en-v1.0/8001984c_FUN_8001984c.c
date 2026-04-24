// Function: FUN_8001984c
// Entry: 8001984c
// Size: 88 bytes

void FUN_8001984c(ushort param_1,ushort param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc9c8;
  if ((param_3 & 1) != 0) {
    DAT_803dc9a8 = param_2;
    DAT_803dc9aa = param_1;
  }
  if ((param_3 & 2) == 0) {
    return;
  }
  iVar1 = DAT_803dc9c8 * 5;
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar1] = 10;
  (&DAT_8033a544)[iVar2 * 5] = (uint)param_1;
  (&DAT_8033a548)[iVar2 * 5] = (uint)param_2;
  return;
}

