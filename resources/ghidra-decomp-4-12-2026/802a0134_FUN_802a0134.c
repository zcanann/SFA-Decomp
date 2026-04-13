// Function: FUN_802a0134
// Entry: 802a0134
// Size: 80 bytes

undefined4 FUN_802a0134(undefined4 param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_80020078(0x2d0);
  if (uVar1 == 0) {
    uVar2 = 0;
  }
  else {
    *(code **)(param_2 + 0x308) = FUN_802a58ac;
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

