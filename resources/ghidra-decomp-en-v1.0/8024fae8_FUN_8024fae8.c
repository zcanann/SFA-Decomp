// Function: FUN_8024fae8
// Entry: 8024fae8
// Size: 356 bytes

void FUN_8024fae8(undefined4 param_1)

{
  uint uVar1;
  uint uVar2;
  
  if (DAT_803ddfe8 != 1) {
    uVar1 = (DAT_800000f8 >> 2) / 0x1e848;
    DAT_803ddff4 = (uVar1 * 0x7b24) / 8000;
    DAT_803ddffc = (uVar1 * 0xa428) / 8000;
    DAT_803de004 = (uVar1 * 42000) / 8000;
    DAT_803de00c = (uVar1 * 63000) / 8000;
    DAT_803de014 = (uVar1 * 3000) / 8000;
    uVar1 = read_volatile_4(DAT_cc006c00);
    DAT_803ddff0 = 0;
    DAT_803ddff8 = 0;
    DAT_803de000 = 0;
    DAT_803de008 = 0;
    DAT_803de010 = 0;
    uVar2 = read_volatile_4(DAT_cc006c04);
    write_volatile_4(DAT_cc006c00,uVar1 & 0xffffffdf | 0x20);
    write_volatile_4(DAT_cc006c04,uVar2 & 0xffff00ff);
    uVar1 = read_volatile_4(DAT_cc006c04);
    write_volatile_4(DAT_cc006c04,uVar1 & 0xffffff00);
    write_volatile_4(DAT_cc006c0c,0);
    FUN_8024f9ac(1);
    FUN_8024f8b8(0);
    DAT_803ddfd8 = 0;
    DAT_803ddfdc = 0;
    DAT_803ddfe0 = param_1;
    FUN_802437c8(5,&LAB_8024fcd4);
    FUN_80243bcc(0x4000000);
    FUN_802437c8(8,&LAB_8024fc58);
    FUN_80243bcc(0x800000);
    DAT_803ddfe8 = 1;
  }
  return;
}

