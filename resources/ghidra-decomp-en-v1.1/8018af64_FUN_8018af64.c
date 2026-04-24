// Function: FUN_8018af64
// Entry: 8018af64
// Size: 84 bytes

void FUN_8018af64(int param_1)

{
  if ((**(byte **)(param_1 + 0xb8) >> 5 & 1) != 0) {
    FUN_800972fc(param_1,2,*(byte *)(*(int *)(param_1 + 0x4c) + 0x19) + 6 & 0xff,4,0);
  }
  return;
}

