// Function: FUN_802a78c0
// Entry: 802a78c0
// Size: 128 bytes

undefined4 FUN_802a78c0(undefined4 param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = FUN_80020078(0x970);
  if (uVar1 != 0) {
    FUN_800201ac(0x970,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(0x10,param_1,0xffffffff);
  }
  *(code **)(param_2 + 0x308) = FUN_802a58ac;
  return 2;
}

