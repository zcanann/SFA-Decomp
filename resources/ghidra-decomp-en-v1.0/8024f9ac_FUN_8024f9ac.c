// Function: FUN_8024f9ac
// Entry: 8024f9ac
// Size: 212 bytes

void FUN_8024f9ac(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  
  iVar4 = FUN_8024fa80();
  if (param_1 != iVar4) {
    uVar1 = read_volatile_4(DAT_cc006c00);
    uVar5 = FUN_8024faac();
    uVar6 = FUN_8024fad8();
    FUN_8024fabc(0);
    FUN_8024fa90(0);
    uVar2 = read_volatile_4(DAT_cc006c00);
    uVar3 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar3 & 0xffffffbf);
    uVar7 = FUN_8024377c();
    FUN_8024fdbc();
    uVar3 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar3 | uVar2 & 0x40);
    uVar2 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar2 & 0xffffffdf | 0x20);
    uVar2 = read_volatile_4(DAT_cc006c00);
    write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffd | param_1 << 1);
    FUN_802437a4(uVar7);
    FUN_8024f7d0(uVar1 & 1);
    FUN_8024fa90(uVar5);
    FUN_8024fabc(uVar6);
  }
  return;
}

