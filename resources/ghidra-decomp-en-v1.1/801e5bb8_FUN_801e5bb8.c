// Function: FUN_801e5bb8
// Entry: 801e5bb8
// Size: 124 bytes

void FUN_801e5bb8(int param_1)

{
  (**(code **)(*DAT_803dd6d4 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dd6f4 + 8))(param_1,0xffff,0,0,0);
  if (*(uint *)(param_1 + 0xf8) != 0) {
    FUN_8001f448(*(uint *)(param_1 + 0xf8));
  }
  return;
}

