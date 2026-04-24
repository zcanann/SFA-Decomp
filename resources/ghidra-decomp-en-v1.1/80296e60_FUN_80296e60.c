// Function: FUN_80296e60
// Entry: 80296e60
// Size: 44 bytes

undefined4 FUN_80296e60(int param_1)

{
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0x8b3) != '\0') &&
     (*(char *)(*(int *)(param_1 + 0xb8) + 0x8b4) != '\0')) {
    return 1;
  }
  return 0;
}

