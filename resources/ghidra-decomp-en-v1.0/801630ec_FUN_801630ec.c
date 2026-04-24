// Function: FUN_801630ec
// Entry: 801630ec
// Size: 188 bytes

void FUN_801630ec(int param_1)

{
  int iVar1;
  
  FUN_8002b9ac();
  iVar1 = FUN_8002e0b4(0x1723);
  if (*(int *)(param_1 + 0xf4) == 0) {
    if (*(short *)(param_1 + 0xa0) != 0x208) {
      FUN_80030334((double)FLOAT_803e2f34,param_1,0x208,0);
    }
    FUN_8002fa48((double)FLOAT_803e2f38,(double)FLOAT_803db414,param_1,0);
    if ((iVar1 != 0) &&
       (iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1a)), iVar1 != 0)) {
      *(undefined4 *)(param_1 + 0xf4) = 1;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      FUN_80035f00(param_1);
    }
  }
  return;
}

