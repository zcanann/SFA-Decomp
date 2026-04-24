// Function: FUN_802876f8
// Entry: 802876f8
// Size: 64 bytes

void FUN_802876f8(int param_1,char param_2)

{
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  if (param_2 == '\0') {
    FUN_800034e4(param_1 + 0x10,0,0x880);
  }
  return;
}

