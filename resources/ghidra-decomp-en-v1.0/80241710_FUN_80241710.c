// Function: FUN_80241710
// Entry: 80241710
// Size: 444 bytes

void FUN_80241710(void)

{
  ushort uVar1;
  ushort uVar2;
  undefined2 uVar3;
  ushort uVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = FUN_802416f0();
  FUN_80003494(iVar5 + -0x80,0x81000000,0x80);
  FUN_80003494(0x81000000,&DAT_8032c520,0x80);
  FUN_802419e8(0x81000000,0x80);
  write_volatile_2(DAT_cc005012,0x43);
  write_volatile_2(DAT_cc00500a,0x8ac);
  uVar1 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar1 | 1);
  do {
    uVar1 = read_volatile_2(DAT_cc00500a);
  } while ((uVar1 & 1) != 0);
  write_volatile_2(DAT_cc005000,0);
  do {
    uVar1 = read_volatile_2(DAT_cc005004);
  } while ((uVar1 & 0x8000) != 0);
  write_volatile_4(0xcc005020,0x1000000);
  write_volatile_4(0xcc005024,0);
  write_volatile_4(0xcc005028,0x20);
  uVar1 = read_volatile_2(DAT_cc00500a);
  while( true ) {
    if ((uVar1 & 0x20) != 0) break;
    uVar1 = read_volatile_2(DAT_cc00500a);
  }
  write_volatile_2(DAT_cc00500a,uVar1);
  iVar5 = FUN_80246c68();
  do {
    iVar6 = FUN_80246c68();
  } while (iVar6 - iVar5 < 0x892);
  write_volatile_4(0xcc005020,0x1000000);
  write_volatile_4(0xcc005024,0);
  write_volatile_4(0xcc005028,0x20);
  uVar1 = read_volatile_2(DAT_cc00500a);
  while( true ) {
    if ((uVar1 & 0x20) != 0) break;
    uVar1 = read_volatile_2(DAT_cc00500a);
  }
  write_volatile_2(DAT_cc00500a,uVar1);
  uVar2 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar2 & 0xf7ff);
  do {
    uVar2 = read_volatile_2(DAT_cc00500a);
  } while ((uVar2 & 0x400) != 0);
  uVar2 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar2 & 0xfffb);
  uVar2 = read_volatile_2(DAT_cc005004);
  while( true ) {
    if ((uVar2 & 0x8000) != 0) break;
    uVar2 = read_volatile_2(DAT_cc005004);
  }
  uVar4 = read_volatile_2(DAT_cc00500a);
  uVar3 = read_volatile_2(DAT_cc005006);
  write_volatile_2(DAT_cc00500a,uVar4 | 4);
  write_volatile_2(DAT_cc00500a,0x8ac);
  uVar4 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar4 | 1);
  do {
    uVar4 = read_volatile_2(DAT_cc00500a);
  } while ((uVar4 & 1) != 0);
  iVar5 = FUN_802416f0(uVar1,uVar3,uVar2);
  FUN_80003494(0x81000000,iVar5 + -0x80,0x80);
  return;
}

