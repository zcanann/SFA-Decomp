// Function: FUN_80258f3c
// Entry: 80258f3c
// Size: 124 bytes

void FUN_80258f3c(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = countLeadingZeros((param_1 & 1) - 1);
  uVar2 = uVar1 >> 5 & 0xff;
  *(uint *)(DAT_803dc5a8 + 0x1ec) = *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xfffffffe | uVar2;
  uVar1 = countLeadingZeros((param_1 & 2) - 2);
  uVar1 = uVar1 >> 4 & 0x1fe;
  *(uint *)(DAT_803dc5a8 + 0x1ec) = *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xfffffffd | uVar1;
  *(uint *)(DAT_803dc5a8 + 0x1fc) = *(uint *)(DAT_803dc5a8 + 0x1fc) & 0xfffffffe | uVar2;
  *(uint *)(DAT_803dc5a8 + 0x1fc) = *(uint *)(DAT_803dc5a8 + 0x1fc) & 0xfffffffd | uVar1;
  return;
}

