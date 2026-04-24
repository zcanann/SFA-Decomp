// Function: FUN_800198a4
// Entry: 800198a4
// Size: 100 bytes

void FUN_800198a4(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc9c8;
  if (DAT_803dc96c != 0) {
    *(short *)(&DAT_802c7418 + param_1 * 0x20) = (short)param_2;
    *(short *)(&DAT_802c741a + param_1 * 0x20) = (short)param_3;
    return;
  }
  iVar1 = DAT_803dc9c8 * 5;
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar1] = 4;
  (&DAT_8033a544)[iVar2 * 5] = param_1;
  (&DAT_8033a548)[iVar2 * 5] = param_2;
  (&DAT_8033a54c)[iVar2 * 5] = param_3;
  return;
}

