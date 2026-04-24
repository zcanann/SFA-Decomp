// Function: FUN_801c53b0
// Entry: 801c53b0
// Size: 144 bytes

void FUN_801c53b0(int param_1,int param_2)

{
  (**(code **)(*DAT_803dca54 + 0x24))(*(undefined4 *)(param_1 + 0xb8));
  (**(code **)(*DAT_803dca74 + 8))(param_1,0xffff,0,0,0);
  if ((*(int *)(param_1 + 200) != 0) && (param_2 == 0)) {
    FUN_8002cbc4();
  }
  return;
}

