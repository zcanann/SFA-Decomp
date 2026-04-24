// Function: FUN_80183b04
// Entry: 80183b04
// Size: 64 bytes

undefined4 FUN_80183b04(int param_1)

{
  if (*(short *)(param_1 + 0xb4) != -1) {
    (**(code **)(*DAT_803dca50 + 0x4c))();
  }
  return 0;
}

