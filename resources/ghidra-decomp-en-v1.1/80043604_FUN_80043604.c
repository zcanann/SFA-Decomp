// Function: FUN_80043604
// Entry: 80043604
// Size: 84 bytes

int FUN_80043604(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  if (param_3 == 1) {
    DAT_803dc210 = 0xfffffffe;
    uRam803dc214 = 0xfffffffe;
    return -1;
  }
  iVar1 = (&DAT_803dc210)[param_2];
  if ((param_1 != iVar1) && (iVar1 != -2)) {
    return iVar1;
  }
  (&DAT_803dc210)[param_2] = 0xfffffffe;
  return -1;
}

