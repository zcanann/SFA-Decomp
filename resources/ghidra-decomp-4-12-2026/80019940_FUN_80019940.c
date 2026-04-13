// Function: FUN_80019940
// Entry: 80019940
// Size: 104 bytes

void FUN_80019940(byte param_1,byte param_2,byte param_3,byte param_4)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dd648;
  if (DAT_803dd5ec != 0) {
    DAT_803dd627 = param_1;
    DAT_803dd626 = param_2;
    DAT_803dd625 = param_3;
    DAT_803dd624 = param_4;
    return;
  }
  iVar1 = DAT_803dd648 * 5;
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 3;
  (&DAT_8033b1a4)[iVar2 * 5] = (uint)param_1;
  (&DAT_8033b1a8)[iVar2 * 5] = (uint)param_2;
  (&DAT_8033b1ac)[iVar2 * 5] = (uint)param_3;
  (&DAT_8033b1b0)[iVar2 * 5] = (uint)param_4;
  return;
}

