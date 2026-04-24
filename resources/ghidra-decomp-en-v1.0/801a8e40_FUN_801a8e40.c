// Function: FUN_801a8e40
// Entry: 801a8e40
// Size: 224 bytes

void FUN_801a8e40(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (iVar1 == 0) {
    *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803db410;
    if (*(int *)(param_1 + 0xf4) < 0) {
      uVar2 = FUN_800221a0(0x46,0xf0);
      *(undefined4 *)(param_1 + 0xf4) = uVar2;
      uVar2 = FUN_800221a0(0x1e,0x3c);
      *(undefined4 *)(param_1 + 0xf8) = uVar2;
    }
    if (*(int *)(param_1 + 0xf8) != 0) {
      *(uint *)(param_1 + 0xf8) = *(int *)(param_1 + 0xf8) - (uint)DAT_803db410;
      if (*(int *)(param_1 + 0xf8) < 1) {
        *(undefined4 *)(param_1 + 0xf8) = 0;
      }
      else {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x724,0,2,0xffffffff,0);
        FUN_8000da58(param_1,0x450);
      }
    }
  }
  return;
}

