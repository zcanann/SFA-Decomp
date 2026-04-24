// Function: FUN_80258ac0
// Entry: 80258ac0
// Size: 100 bytes

void FUN_80258ac0(int param_1,uint param_2,uint param_3)

{
  param_1 = param_1 * 4;
  *(uint *)(DAT_803dc5a8 + param_1 + 0xb8) =
       *(uint *)(DAT_803dc5a8 + param_1 + 0xb8) & 0xfffbffff | (param_2 & 0xff) << 0x12;
  *(uint *)(DAT_803dc5a8 + param_1 + 0xb8) =
       *(uint *)(DAT_803dc5a8 + param_1 + 0xb8) & 0xfff7ffff | (param_3 & 0xff) << 0x13;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + param_1 + 0xb8));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

