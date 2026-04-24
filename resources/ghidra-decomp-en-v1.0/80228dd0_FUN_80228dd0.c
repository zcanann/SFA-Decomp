// Function: FUN_80228dd0
// Entry: 80228dd0
// Size: 260 bytes

void FUN_80228dd0(int param_1,int param_2)

{
  **(undefined2 **)(param_1 + 0xb8) = *(undefined2 *)(param_2 + 0x1e);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  DAT_803ddd80 = FUN_80013ec8(0xa6,1);
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x545,0,0x802,0xffffffff,0);
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x545,0,0x802,0xffffffff,0);
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x545,0,0x802,0xffffffff,0);
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x546,0,0x802,0xffffffff,0);
  return;
}

