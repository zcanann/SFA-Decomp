// Function: FUN_80019884
// Entry: 80019884
// Size: 88 bytes

void FUN_80019884(ushort param_1,ushort param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dd648;
  if ((param_3 & 1) != 0) {
    DAT_803dd628 = param_2;
    DAT_803dd62a = param_1;
  }
  if ((param_3 & 2) == 0) {
    return;
  }
  iVar1 = DAT_803dd648 * 5;
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 10;
  (&DAT_8033b1a4)[iVar2 * 5] = (uint)param_1;
  (&DAT_8033b1a8)[iVar2 * 5] = (uint)param_2;
  return;
}

