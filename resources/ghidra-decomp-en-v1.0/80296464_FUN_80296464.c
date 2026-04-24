// Function: FUN_80296464
// Entry: 80296464
// Size: 16 bytes

uint FUN_80296464(int param_1)

{
  return *(uint *)(*(int *)(param_1 + 0xb8) + 0x360) & 1;
}

