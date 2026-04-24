// Function: FUN_80024060
// Entry: 80024060
// Size: 316 bytes

void FUN_80024060(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  DAT_803dd7c2 = 0;
  iVar1 = FUN_80241df0();
  iVar2 = FUN_80241de8();
  iVar1 = (iVar2 - iVar1) + -0x6c0720;
  DAT_803dd798 = iVar1;
  piVar3 = FUN_80241b84(DAT_803dd198,iVar1);
  FUN_802420e0((uint)piVar3,iVar1);
  FUN_80023f98((int)piVar3,iVar1,0xfa);
  DAT_803de110 = FUN_80241b84(DAT_803dd198,0x6ed);
  DAT_803dd77c = DAT_803de110 + 0x1bb;
  piVar3 = FUN_80241b84(DAT_803dd198,0x1c0000);
  FUN_802420e0((uint)piVar3,0x1c0000);
  FUN_80023f98((int)piVar3,0x1c0000,0x352);
  piVar3 = FUN_80241b84(DAT_803dd198,0x9ffa0);
  FUN_802420e0((uint)piVar3,0x9ffa0);
  FUN_80023f98((int)piVar3,0x9ffa0,0x352);
  piVar3 = FUN_80241b84(DAT_803dd198,0x45ffa0);
  FUN_802420e0((uint)piVar3,0x45ffa0);
  FUN_80023f98((int)piVar3,0x45ffa0,0x244);
  DAT_803dd794 = DAT_803dd794 + 1;
  DAT_803dd7bc = 2;
  DAT_803dd7c0 = 0;
  return;
}

