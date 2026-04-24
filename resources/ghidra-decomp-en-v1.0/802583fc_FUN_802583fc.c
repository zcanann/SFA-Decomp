// Function: FUN_802583fc
// Entry: 802583fc
// Size: 184 bytes

void FUN_802583fc(uint param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8024377c();
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_1 & 0xffff | 0x48000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_1 & 0xffff | 0x47000000);
  if (*(int *)(DAT_803dc5a8 + 0x4f4) != 0) {
    FUN_802587fc();
  }
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  FUN_8024037c();
  FUN_802437a4(uVar1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

