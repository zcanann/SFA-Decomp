// Function: FUN_802a7160
// Entry: 802a7160
// Size: 128 bytes

undefined4 FUN_802a7160(undefined4 param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(0x970);
  if (iVar1 != 0) {
    FUN_800200e8(0x970,0);
    (**(code **)(*DAT_803dca54 + 0x48))(0x10,param_1,0xffffffff);
  }
  *(code **)(param_2 + 0x308) = FUN_802a514c;
  return 2;
}

