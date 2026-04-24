// Function: FUN_801a70f8
// Entry: 801a70f8
// Size: 220 bytes

void FUN_801a70f8(int param_1)

{
  int iVar1;
  uint uVar2;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  iVar1 = FUN_800e8a48();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  uVar2 = FUN_80020078(0xf33);
  *(uint *)(param_1 + 0xf8) = uVar2;
  *(code **)(param_1 + 0xbc) = FUN_801a6bec;
  iVar1 = FUN_8004832c(0x12);
  FUN_80043604(iVar1,0,0);
  FLOAT_803de7a8 = FLOAT_803e5160;
  DAT_803de7ac = 0;
  FUN_8000a538((int *)0xcc,0);
  FUN_8000a538((int *)0xdb,0);
  FUN_8000a538((int *)0xf2,0);
  FUN_8000a538((int *)0xce,0);
  FUN_8000a538((int *)0xc2,0);
  FUN_800201ac(0xdcf,0);
  return;
}

