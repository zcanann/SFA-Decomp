// Function: FUN_800607e4
// Entry: 800607e4
// Size: 16 bytes

uint FUN_800607e4(int param_1)

{
  return (*(uint *)(param_1 + 0x10) & 0xff0000) >> 0x10;
}

