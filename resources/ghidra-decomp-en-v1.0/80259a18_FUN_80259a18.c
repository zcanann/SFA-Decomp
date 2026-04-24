// Function: FUN_80259a18
// Entry: 80259a18
// Size: 40 bytes

void FUN_80259a18(int param_1,byte *param_2)

{
  *(uint *)(param_1 + 0xc) =
       (uint)param_2[3] | (uint)param_2[2] << 8 | (uint)*param_2 << 0x18 | (uint)param_2[1] << 0x10;
  return;
}

