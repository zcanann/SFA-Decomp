// Function: FUN_8025ca04
// Entry: 8025ca04
// Size: 52 bytes

void FUN_8025ca04(uint param_1)

{
  *(uint *)(DAT_803dd210 + 0x204) =
       *(uint *)(DAT_803dd210 + 0x204) & 0xffffc3ff | ((param_1 & 0xff) - 1) * 0x400;
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 4;
  return;
}

