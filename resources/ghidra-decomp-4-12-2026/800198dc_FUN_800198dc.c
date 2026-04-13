// Function: FUN_800198dc
// Entry: 800198dc
// Size: 100 bytes

void FUN_800198dc(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dd648;
  if (DAT_803dd5ec != 0) {
    *(short *)(&DAT_802c7b98 + param_1 * 0x20) = (short)param_2;
    *(short *)(&DAT_802c7b9a + param_1 * 0x20) = (short)param_3;
    return;
  }
  iVar1 = DAT_803dd648 * 5;
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 4;
  (&DAT_8033b1a4)[iVar2 * 5] = param_1;
  (&DAT_8033b1a8)[iVar2 * 5] = param_2;
  (&DAT_8033b1ac)[iVar2 * 5] = param_3;
  return;
}

