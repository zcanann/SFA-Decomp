// Function: FUN_802418cc
// Entry: 802418cc
// Size: 216 bytes

void FUN_802418cc(void)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  
  write_volatile_2(DAT_cc00500a,0x804);
  uVar1 = read_volatile_2(DAT_cc005036);
  write_volatile_2(DAT_cc005036,uVar1 & 0x7fff);
  uVar1 = read_volatile_2(DAT_cc00500a);
  while ((uVar1 & 0x400) != 0) {
    uVar1 = read_volatile_2(DAT_cc00500a);
  }
  uVar1 = read_volatile_2(DAT_cc00500a);
  while ((uVar1 & 0x200) != 0) {
    uVar1 = read_volatile_2(DAT_cc00500a);
  }
  write_volatile_2(DAT_cc00500a,0x8ac);
  write_volatile_2(DAT_cc005000,0);
  do {
    uVar1 = read_volatile_2(DAT_cc005004);
  } while ((uVar1 & 0x8000) != 0);
  iVar2 = FUN_80246c68();
  do {
    iVar3 = FUN_80246c68();
  } while (iVar3 - iVar2 < 0x2c);
  uVar1 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar1 | 1);
  uVar1 = read_volatile_2(DAT_cc00500a);
  while ((uVar1 & 1) != 0) {
    uVar1 = read_volatile_2(DAT_cc00500a);
  }
  return;
}

