// Function: FUN_8017c0f4
// Entry: 8017c0f4
// Size: 192 bytes

void FUN_8017c0f4(int param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_80020078((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (uVar1 != 0) {
    iVar2 = FUN_800395a4(param_1,0);
    if (iVar2 != 0) {
      *(short *)(iVar2 + 8) = *(short *)(iVar2 + 8) + (short)((int)FLOAT_803dc074 << 3);
      if (0x131e < (int)*(short *)(iVar2 + 8) + (int)FLOAT_803dc074 * 8) {
        *(undefined2 *)(iVar2 + 8) = 0x131f;
      }
      FUN_80137cd0();
    }
    FUN_80036018(param_1);
  }
  return;
}

