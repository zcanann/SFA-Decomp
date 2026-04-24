// Function: FUN_8017bb9c
// Entry: 8017bb9c
// Size: 192 bytes

void FUN_8017bb9c(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (iVar1 != 0) {
    iVar1 = FUN_800394ac(param_1,0,0);
    if (iVar1 != 0) {
      *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + (short)((int)FLOAT_803db414 << 3);
      if (0x131e < (int)*(short *)(iVar1 + 8) + (int)FLOAT_803db414 * 8) {
        *(undefined2 *)(iVar1 + 8) = 0x131f;
      }
      FUN_80137948(&DAT_803dbd90,(int)*(short *)(iVar1 + 8));
    }
    FUN_80035f20(param_1);
  }
  return;
}

