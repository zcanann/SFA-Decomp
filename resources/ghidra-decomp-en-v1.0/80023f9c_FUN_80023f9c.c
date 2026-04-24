// Function: FUN_80023f9c
// Entry: 80023f9c
// Size: 316 bytes

void FUN_80023f9c(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  DAT_803dcb42 = 0;
  iVar1 = FUN_802416f8();
  iVar2 = FUN_802416f0();
  iVar1 = (iVar2 - iVar1) + -0x6c0720;
  DAT_803dcb18 = iVar1;
  uVar3 = FUN_8024148c(DAT_803dc530,iVar1);
  FUN_802419e8(uVar3,iVar1);
  FUN_80023ed4(uVar3,iVar1,0xfa);
  DAT_803dd498 = FUN_8024148c(DAT_803dc530,0x6ed);
  DAT_803dcafc = DAT_803dd498 + 0x6ec;
  uVar3 = FUN_8024148c(DAT_803dc530,0x1c0000);
  FUN_802419e8(uVar3,0x1c0000);
  FUN_80023ed4(uVar3,0x1c0000,0x352);
  uVar3 = FUN_8024148c(DAT_803dc530,0x9ffa0);
  FUN_802419e8(uVar3,0x9ffa0);
  FUN_80023ed4(uVar3,0x9ffa0,0x352);
  uVar3 = FUN_8024148c(DAT_803dc530,0x45ffa0);
  FUN_802419e8(uVar3,0x45ffa0);
  FUN_80023ed4(uVar3,0x45ffa0,0x244);
  DAT_803dcb14 = DAT_803dcb14 + 1;
  DAT_803dcb3c = 2;
  DAT_803dcb40 = 0;
  return;
}

