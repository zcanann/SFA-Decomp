// Function: FUN_8021a050
// Entry: 8021a050
// Size: 112 bytes

void FUN_8021a050(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (iVar1 == 0) {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    FUN_80035f20(param_1);
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    FUN_80035f00(param_1);
  }
  return;
}

