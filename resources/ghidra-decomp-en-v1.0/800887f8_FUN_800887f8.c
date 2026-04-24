// Function: FUN_800887f8
// Entry: 800887f8
// Size: 120 bytes

void FUN_800887f8(byte param_1)

{
  undefined4 uVar1;
  
  DAT_803dd140 = param_1;
  if ((param_1 & 8) == 0) {
    uVar1 = FUN_8002b9ec();
    FUN_80008cbc(uVar1,uVar1,0x136,0);
    FUN_80008cbc(uVar1,uVar1,0x137,0);
    FUN_80008cbc(uVar1,uVar1,0x143,0);
  }
  return;
}

