// Function: FUN_8025be54
// Entry: 8025be54
// Size: 44 bytes

void FUN_8025be54(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x204) =
       *(uint *)(DAT_803dd210 + 0x204) & 0xfff8ffff | (param_1 & 0xff) << 0x10;
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 6;
  return;
}

