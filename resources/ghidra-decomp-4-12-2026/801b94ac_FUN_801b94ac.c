// Function: FUN_801b94ac
// Entry: 801b94ac
// Size: 124 bytes

void FUN_801b94ac(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 == 0) {
    *(undefined *)(iVar2 + 4) = 1;
  }
  else {
    *(undefined *)(iVar2 + 4) = 2;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

