// Function: FUN_80229494
// Entry: 80229494
// Size: 260 bytes

void FUN_80229494(int param_1,int param_2)

{
  **(undefined2 **)(param_1 + 0xb8) = *(undefined2 *)(param_2 + 0x1e);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  DAT_803dea00 = FUN_80013ee8(0xa6);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x545,0,0x802,0xffffffff,0);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x545,0,0x802,0xffffffff,0);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x545,0,0x802,0xffffffff,0);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x546,0,0x802,0xffffffff,0);
  return;
}

