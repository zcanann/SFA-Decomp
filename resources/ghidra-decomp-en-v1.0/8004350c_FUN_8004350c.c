// Function: FUN_8004350c
// Entry: 8004350c
// Size: 84 bytes

int FUN_8004350c(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  if (param_3 == 1) {
    DAT_803db5b0 = 0xfffffffe;
    uRam803db5b4 = 0xfffffffe;
    return -1;
  }
  iVar1 = (&DAT_803db5b0)[param_2];
  if ((param_1 != iVar1) && (iVar1 != -2)) {
    return iVar1;
  }
  (&DAT_803db5b0)[param_2] = 0xfffffffe;
  return -1;
}

