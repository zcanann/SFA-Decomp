// Function: FUN_802154ac
// Entry: 802154ac
// Size: 236 bytes

void FUN_802154ac(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  DAT_803de9d8 = *(undefined4 *)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,DAT_803de9d8,0);
  FUN_800139e8(*DAT_803de9d4);
  if (DAT_803de9c8 != (undefined *)0x0) {
    FUN_80013e4c(DAT_803de9c8);
  }
  if (DAT_803de9d4[0x5e] != 0) {
    FUN_8001f448(DAT_803de9d4[0x5e]);
  }
  iVar2 = 0;
  iVar3 = 0;
  do {
    uVar1 = *(uint *)((int)DAT_803de9d4 + iVar3 + 0x17c);
    if (uVar1 != 0) {
      FUN_800238c4(uVar1);
    }
    iVar3 = iVar3 + 4;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 5);
  DAT_803de9c8 = (undefined *)0x0;
  FUN_8000a538((int *)0x28,0);
  FUN_8000a538((int *)0x93,0);
  FUN_8000a538((int *)0x94,0);
  return;
}

