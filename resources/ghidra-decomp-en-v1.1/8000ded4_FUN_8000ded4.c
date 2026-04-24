// Function: FUN_8000ded4
// Entry: 8000ded4
// Size: 52 bytes

int FUN_8000ded4(int param_1,short *param_2)

{
  int iVar1;
  
  iVar1 = param_1 + *param_2;
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (-0x8001 < iVar1) {
    return iVar1;
  }
  return iVar1 + 0xffff;
}

