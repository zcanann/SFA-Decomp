// Function: FUN_801b8ef8
// Entry: 801b8ef8
// Size: 124 bytes

void FUN_801b8ef8(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 == 0) {
    *(undefined *)(iVar2 + 4) = 1;
  }
  else {
    *(undefined *)(iVar2 + 4) = 2;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

