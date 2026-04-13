// Function: FUN_8021a768
// Entry: 8021a768
// Size: 116 bytes

void FUN_8021a768(undefined2 *param_1,int param_2)

{
  uint uVar1;
  
  FUN_80036018((int)param_1);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    param_1[3] = param_1[3] | 0x4000;
    FUN_80035ff8((int)param_1);
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  return;
}

