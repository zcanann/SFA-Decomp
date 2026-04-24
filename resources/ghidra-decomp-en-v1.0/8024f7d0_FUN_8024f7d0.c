// Function: FUN_8024f7d0
// Entry: 8024f7d0
// Size: 216 bytes

void FUN_8024f7d0(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  uVar1 = FUN_8024f8a8();
  if (param_1 != uVar1) {
    iVar2 = FUN_8024fa80();
    if ((iVar2 == 0) && (param_1 == 1)) {
      uVar3 = FUN_8024fad8();
      uVar4 = FUN_8024faac();
      FUN_8024fabc(0);
      FUN_8024fa90(0);
      uVar5 = FUN_8024377c();
      FUN_8024fdbc();
      uVar1 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar1 & 0xffffffdf | 0x20);
      uVar1 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar1 & 0xfffffffe | 1);
      FUN_802437a4(uVar5);
      FUN_8024fa90(uVar3);
      FUN_8024fabc(uVar4);
    }
    else {
      uVar1 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar1 & 0xfffffffe | param_1);
    }
  }
  return;
}

