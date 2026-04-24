// Function: FUN_80257e74
// Entry: 80257e74
// Size: 140 bytes

void FUN_80257e74(int param_1,uint param_2,uint param_3)

{
  byte bVar1;
  int iVar2;
  
  if (param_1 == 0x19) {
    param_1 = 10;
  }
  bVar1 = (char)param_1 - 9;
  write_volatile_1(DAT_cc008000,8);
  write_volatile_1(DAT_cc008000,bVar1 | 0xa0);
  iVar2 = param_1 + -0x15;
  write_volatile_4(0xcc008000,param_2 & 0x3fffffff);
  if ((-1 < iVar2) && (iVar2 < 4)) {
    *(uint *)(DAT_803dc5a8 + iVar2 * 4 + 0x88) = param_2 & 0x3fffffff;
  }
  write_volatile_1(DAT_cc008000,8);
  write_volatile_1(DAT_cc008000,bVar1 | 0xb0);
  param_1 = param_1 + -0x15;
  write_volatile_4(0xcc008000,param_3 & 0xff);
  if (param_1 < 0) {
    return;
  }
  if (3 < param_1) {
    return;
  }
  *(uint *)(DAT_803dc5a8 + param_1 * 4 + 0x98) = param_3 & 0xff;
  return;
}

