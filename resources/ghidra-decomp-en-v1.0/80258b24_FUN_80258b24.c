// Function: FUN_80258b24
// Entry: 80258b24
// Size: 80 bytes

void FUN_80258b24(int param_1)

{
  if (param_1 == 2) {
    param_1 = 1;
  }
  else if ((param_1 < 2) && (0 < param_1)) {
    param_1 = 2;
  }
  *(uint *)(DAT_803dc5a8 + 0x204) = *(uint *)(DAT_803dc5a8 + 0x204) & 0xffff3fff | param_1 << 0xe;
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 4;
  return;
}

