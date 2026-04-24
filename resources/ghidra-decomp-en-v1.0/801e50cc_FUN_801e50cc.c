// Function: FUN_801e50cc
// Entry: 801e50cc
// Size: 136 bytes

void FUN_801e50cc(int param_1)

{
  int iVar1;
  
  if (((*(short *)(param_1 + 0x46) == 0x173) && (*(int *)(param_1 + 0xf4) == 0)) &&
     (iVar1 = FUN_8001ffb4(0xa4b), iVar1 != 0)) {
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  return;
}

