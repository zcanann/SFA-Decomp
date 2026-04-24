// Function: FUN_80250f0c
// Entry: 80250f0c
// Size: 184 bytes

void FUN_80250f0c(void)

{
  ushort uVar1;
  undefined4 uVar2;
  
  FUN_802510cc(s_DSPInit____Build_Date___s__s_8032e0c8,s_Dec_17_2001_8032e0e8,s_18_25_00_8032e0f4);
  if (DAT_803de060 != 1) {
    uVar2 = FUN_8024377c();
    FUN_802437c8(7,&LAB_8025111c);
    FUN_80243bcc(0x1000000);
    uVar1 = read_volatile_2(DAT_cc00500a);
    write_volatile_2(DAT_cc00500a,uVar1 & 0xff57 | 0x800);
    uVar1 = read_volatile_2(DAT_cc00500a);
    write_volatile_2(DAT_cc00500a,uVar1 & 0xff53);
    DAT_803de070 = 0;
    DAT_803de07c = 0;
    DAT_803de074 = 0;
    DAT_803de078 = 0;
    DAT_803de060 = 1;
    FUN_802437a4(uVar2);
  }
  return;
}

