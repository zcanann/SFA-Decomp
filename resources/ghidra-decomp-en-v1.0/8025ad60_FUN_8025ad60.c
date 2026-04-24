// Function: FUN_8025ad60
// Entry: 8025ad60
// Size: 204 bytes

void FUN_8025ad60(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  
  param_2 = param_2 * 4;
  uVar1 = *(uint *)(DAT_803dc5a8 + param_1 * 4 + 0x45c);
  *(uint *)(DAT_803dc5a8 + param_2 + 0xb8) =
       uVar1 & 0x3ff | *(uint *)(DAT_803dc5a8 + param_2 + 0xb8) & 0xffff0000;
  *(uint *)(DAT_803dc5a8 + param_2 + 0xd8) =
       uVar1 >> 10 & 0x3ff | *(uint *)(DAT_803dc5a8 + param_2 + 0xd8) & 0xffff0000;
  uVar2 = *(uint *)(DAT_803dc5a8 + param_1 * 4 + 0x47c);
  uVar1 = countLeadingZeros(1 - (uVar2 & 3));
  *(uint *)(DAT_803dc5a8 + param_2 + 0xb8) =
       *(uint *)(DAT_803dc5a8 + param_2 + 0xb8) & 0xfffeffff | (uVar1 & 0x1fe0) << 0xb;
  uVar1 = countLeadingZeros(1 - (uVar2 >> 2 & 3));
  *(uint *)(DAT_803dc5a8 + param_2 + 0xd8) =
       *(uint *)(DAT_803dc5a8 + param_2 + 0xd8) & 0xfffeffff | (uVar1 & 0x1fe0) << 0xb;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + param_2 + 0xb8));
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + param_2 + 0xd8));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

