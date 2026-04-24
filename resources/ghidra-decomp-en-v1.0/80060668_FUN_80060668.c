// Function: FUN_80060668
// Entry: 80060668
// Size: 16 bytes

uint FUN_80060668(int param_1)

{
  return (*(uint *)(param_1 + 0x10) & 0xff0000) >> 0x10;
}

