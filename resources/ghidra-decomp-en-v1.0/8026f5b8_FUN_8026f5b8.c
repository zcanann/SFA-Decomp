// Function: FUN_8026f5b8
// Entry: 8026f5b8
// Size: 120 bytes

void FUN_8026f5b8(int param_1)

{
  if ((*(uint *)(param_1 + 0x118) & 0x20000) != 0) {
    return;
  }
  if (*(char *)(param_1 + 0x131) == '\x01') {
    if ((*(uint *)(param_1 + 0x118) & 0x1000) == 0) {
      *(undefined4 *)(param_1 + 0x13c) = 0;
    }
    else {
      *(undefined4 *)(param_1 + 0x13c) = *(undefined4 *)(param_1 + 0x134);
    }
  }
  else {
    *(undefined4 *)(param_1 + 0x13c) = *(undefined4 *)(param_1 + 0x134);
  }
  *(uint *)(param_1 + 0x138) = (uint)*(byte *)(param_1 + 0x130) << 0x10;
  return;
}

