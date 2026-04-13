// Function: FUN_80259a80
// Entry: 80259a80
// Size: 28 bytes

void FUN_80259a80(int param_1)

{
  *(uint *)(DAT_803dd210 + 0x1ec) = *(uint *)(DAT_803dd210 + 0x1ec) & 0xfffffe7f | param_1 << 7;
  return;
}

