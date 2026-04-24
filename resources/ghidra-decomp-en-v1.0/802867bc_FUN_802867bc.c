// Function: FUN_802867bc
// Entry: 802867bc
// Size: 160 bytes

void FUN_802867bc(undefined4 param_1)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  if (DAT_803de3e8 == 0) {
    uVar1 = FUN_802416f8();
    uVar2 = FUN_802416f0();
    iVar3 = FUN_80241614(uVar1,uVar2,1);
    FUN_80241708();
    FUN_80241684(iVar3 + 0x1fU & 0xffffffe0,uVar2 & 0xffffffe0);
    FUN_80241604();
    FUN_80241708(uVar2 & 0xffffffe0);
    DAT_803de3e8 = 1;
  }
  FUN_80241588(0,param_1);
  return;
}

