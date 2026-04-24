// Function: FUN_8001983c
// Entry: 8001983c
// Size: 72 bytes

void FUN_8001983c(uint param_1)

{
  int iVar1;
  
  if ((param_1 & 1) != 0) {
    DAT_803dd62a = 0;
    DAT_803dd628 = 0;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  iVar1 = DAT_803dd648 * 5;
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 0xb;
  return;
}

