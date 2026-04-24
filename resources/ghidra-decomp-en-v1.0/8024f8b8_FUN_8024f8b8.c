// Function: FUN_8024f8b8
// Entry: 8024f8b8
// Size: 224 bytes

void FUN_8024f8b8(int param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  
  iVar3 = FUN_8024f998();
  if ((param_1 != iVar3) &&
     (uVar1 = read_volatile_4(DAT_cc006c00), write_volatile_4(DAT_cc006c00,uVar1 & 0xffffffbf),
     param_1 == 0)) {
    uVar4 = FUN_8024faac();
    uVar5 = FUN_8024fad8();
    uVar1 = read_volatile_4(DAT_cc006c00);
    iVar3 = FUN_8024fa80();
    FUN_8024fa90(0);
    FUN_8024fabc(0);
    uVar6 = FUN_8024377c();
    FUN_8024fdbc();
    uVar2 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar2 & 0xffffffdf | 0x20);
    uVar2 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffd | iVar3 << 1);
    uVar2 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffe | uVar1 & 1);
    uVar1 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar1 | 0x40);
    FUN_802437a4(uVar6);
    FUN_8024fa90(uVar4);
    FUN_8024fabc(uVar5);
  }
  return;
}

