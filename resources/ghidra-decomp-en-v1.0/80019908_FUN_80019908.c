// Function: FUN_80019908
// Entry: 80019908
// Size: 104 bytes

void FUN_80019908(byte param_1,byte param_2,byte param_3,byte param_4)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc9c8;
  if (DAT_803dc96c != 0) {
    DAT_803dc9a4 = param_4;
    DAT_803dc9a5 = param_3;
    DAT_803dc9a6 = param_2;
    DAT_803dc9a7 = param_1;
    return;
  }
  iVar1 = DAT_803dc9c8 * 5;
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar1] = 3;
  (&DAT_8033a544)[iVar2 * 5] = (uint)param_1;
  (&DAT_8033a548)[iVar2 * 5] = (uint)param_2;
  (&DAT_8033a54c)[iVar2 * 5] = (uint)param_3;
  (&DAT_8033a550)[iVar2 * 5] = (uint)param_4;
  return;
}

