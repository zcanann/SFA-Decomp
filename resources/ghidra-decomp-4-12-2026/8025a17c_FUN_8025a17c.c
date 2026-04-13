// Function: FUN_8025a17c
// Entry: 8025a17c
// Size: 40 bytes

void FUN_8025a17c(int param_1,byte *param_2)

{
  *(uint *)(param_1 + 0xc) =
       (uint)param_2[3] | (uint)param_2[2] << 8 | (uint)*param_2 << 0x18 | (uint)param_2[1] << 0x10;
  return;
}

