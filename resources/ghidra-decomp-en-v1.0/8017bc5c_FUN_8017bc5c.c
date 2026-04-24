// Function: FUN_8017bc5c
// Entry: 8017bc5c
// Size: 148 bytes

void FUN_8017bc5c(undefined2 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x26);
  iVar1 = FUN_800394ac(param_1,0,0);
  if (iVar1 != 0) {
    *(undefined2 *)(iVar1 + 8) = 0x800;
  }
  *param_1 = (short)((int)*(char *)(iVar2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  FUN_80035f00(param_1);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
  if (iVar1 != 0) {
    FUN_80035f20(param_1);
  }
  return;
}

