// Function: FUN_802500d4
// Entry: 802500d4
// Size: 188 bytes

undefined4 FUN_802500d4(undefined4 param_1,undefined4 param_2)

{
  ushort uVar1;
  ushort uVar2;
  undefined4 uVar3;
  
  if (DAT_803de034 == 1) {
    uVar3 = 0x4000;
  }
  else {
    uVar3 = FUN_8024377c();
    DAT_803de018 = 0;
    FUN_802437c8(6,&LAB_802501a0);
    FUN_80243bcc(0x2000000);
    DAT_803de028 = 0x4000;
    uVar1 = read_volatile_2(DAT_cc00501a);
    uVar2 = read_volatile_2(DAT_cc00501a);
    write_volatile_2(DAT_cc00501a,uVar2 & 0xff | uVar1 & 0xff00);
    DAT_803de02c = param_2;
    DAT_803de030 = param_1;
    FUN_80250218();
    DAT_803de034 = 1;
    FUN_802437a4(uVar3);
    uVar3 = DAT_803de028;
  }
  return uVar3;
}

