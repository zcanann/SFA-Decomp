// Function: FUN_8025a748
// Entry: 8025a748
// Size: 424 bytes

void FUN_8025a748(uint *param_1,uint *param_2,int param_3)

{
  int iVar1;
  
  *param_1 = *param_1 & 0xffffff | (uint)(byte)(&DAT_803dc5c0)[param_3] << 0x18;
  param_1[1] = param_1[1] & 0xffffff | (uint)(byte)(&DAT_803dc5c8)[param_3] << 0x18;
  param_1[2] = param_1[2] & 0xffffff | (uint)(byte)(&DAT_803dc5d0)[param_3] << 0x18;
  *param_2 = *param_2 & 0xffffff | (uint)(byte)(&DAT_803dc5d8)[param_3] << 0x18;
  param_2[1] = param_2[1] & 0xffffff | (uint)(byte)(&DAT_803dc5e0)[param_3] << 0x18;
  param_1[3] = param_1[3] & 0xffffff | (uint)(byte)(&DAT_803dc5e8)[param_3] << 0x18;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*param_1);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_1[1]);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_1[2]);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*param_2);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_2[1]);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_1[3]);
  if ((*(byte *)((int)param_1 + 0x1f) & 2) == 0) {
    iVar1 = (**(code **)(DAT_803dc5a8 + 0x414))(param_1[6]);
    *(uint *)(iVar1 + 4) =
         *(uint *)(iVar1 + 4) & 0xffffff | (uint)(byte)(&DAT_803dc5f0)[param_3] << 0x18;
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*(undefined4 *)(iVar1 + 4));
  }
  *(uint *)(DAT_803dc5a8 + param_3 * 4 + 0x45c) = param_1[2];
  *(uint *)(DAT_803dc5a8 + param_3 * 4 + 0x47c) = *param_1;
  *(uint *)(DAT_803dc5a8 + 0x4f4) = *(uint *)(DAT_803dc5a8 + 0x4f4) | 1;
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

