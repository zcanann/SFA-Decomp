// Function: FUN_800d57bc
// Entry: 800d57bc
// Size: 140 bytes

undefined4 FUN_800d57bc(uint param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  *param_2 = -1;
  if ((int)param_1 < 0) {
    return 0;
  }
  iVar1 = DAT_803de090 + -1;
  iVar2 = 0;
  while( true ) {
    while( true ) {
      if (iVar1 < iVar2) {
        *param_2 = -1;
        return 0;
      }
      iVar3 = iVar1 + iVar2 >> 1;
      if (param_1 <= (uint)(&DAT_8039d0b8)[iVar3 * 2]) break;
      iVar2 = iVar3 + 1;
    }
    if ((uint)(&DAT_8039d0b8)[iVar3 * 2] <= param_1) break;
    iVar1 = iVar3 + -1;
  }
  *param_2 = iVar3;
  return (&DAT_8039d0bc)[iVar3 * 2];
}

