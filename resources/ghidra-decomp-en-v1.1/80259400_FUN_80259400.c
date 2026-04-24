// Function: FUN_80259400
// Entry: 80259400
// Size: 192 bytes

void FUN_80259400(uint param_1,uint param_2,uint param_3,uint param_4)

{
  *(undefined4 *)(DAT_803dd210 + 0x1f0) = 0;
  *(uint *)(DAT_803dd210 + 0x1f0) = *(uint *)(DAT_803dd210 + 0x1f0) & 0xfffffc00 | param_1 & 0xffff;
  *(uint *)(DAT_803dd210 + 0x1f0) =
       *(uint *)(DAT_803dd210 + 0x1f0) & 0xfff003ff | (param_2 & 0xffff) << 10;
  *(uint *)(DAT_803dd210 + 0x1f0) = *(uint *)(DAT_803dd210 + 0x1f0) & 0xffffff | 0x49000000;
  *(undefined4 *)(DAT_803dd210 + 500) = 0;
  *(uint *)(DAT_803dd210 + 500) =
       *(uint *)(DAT_803dd210 + 500) & 0xfffffc00 | (param_3 & 0xffff) - 1;
  *(uint *)(DAT_803dd210 + 500) =
       *(uint *)(DAT_803dd210 + 500) & 0xfff003ff | ((param_4 & 0xffff) - 1) * 0x400;
  *(uint *)(DAT_803dd210 + 500) = *(uint *)(DAT_803dd210 + 500) & 0xffffff | 0x4a000000;
  return;
}

