// Function: FUN_8021a0c0
// Entry: 8021a0c0
// Size: 116 bytes

void FUN_8021a0c0(undefined2 *param_1,int param_2)

{
  int iVar1;
  
  FUN_80035f20();
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 != 0) {
    param_1[3] = param_1[3] | 0x4000;
    FUN_80035f00(param_1);
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  return;
}

