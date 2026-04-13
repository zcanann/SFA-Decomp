// Function: FUN_80286f20
// Entry: 80286f20
// Size: 160 bytes

void FUN_80286f20(int param_1)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  if (DAT_803df068 == 0) {
    uVar1 = FUN_80241df0();
    uVar2 = FUN_80241de8();
    iVar3 = FUN_80241d0c(uVar1,uVar2,1);
    FUN_80241e00(iVar3);
    iVar3 = FUN_80241d7c(iVar3 + 0x1fU & 0xffffffe0,uVar2 & 0xffffffe0);
    FUN_80241cfc(iVar3);
    FUN_80241e00(uVar2 & 0xffffffe0);
    DAT_803df068 = 1;
  }
  FUN_80241c80(0,param_1);
  return;
}

