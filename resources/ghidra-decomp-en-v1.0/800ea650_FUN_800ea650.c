// Function: FUN_800ea650
// Entry: 800ea650
// Size: 260 bytes

void FUN_800ea650(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int *local_18 [3];
  
  local_18[0] = (int *)0x0;
  if (DAT_803dd4ac != param_1) {
    FUN_8001f768(local_18,0x19);
    iVar2 = 0;
    for (piVar1 = local_18[0]; *piVar1 != -1; piVar1 = piVar1 + 1) {
      iVar2 = iVar2 + 1;
    }
    if ((param_1 < 0) || (iVar2 + -1 <= param_1)) {
      param_1 = 0;
    }
    iVar3 = local_18[0][param_1];
    iVar2 = local_18[0][param_1 + 1] - iVar3;
    if (iVar2 != DAT_803dd4a4) {
      if (DAT_803dd4a0 != 0) {
        FUN_80023800();
      }
      DAT_803dd4a0 = FUN_80023cc8(iVar2,2,0);
    }
    DAT_803dd4a4 = iVar2;
    FUN_8001f71c(DAT_803dd4a0,0x18,iVar3,iVar2);
    FUN_80023800(local_18[0]);
    DAT_803dd4ac = param_1;
  }
  DAT_803dd4a8 = 1;
  return;
}

