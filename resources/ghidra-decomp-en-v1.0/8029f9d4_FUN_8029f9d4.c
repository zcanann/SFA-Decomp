// Function: FUN_8029f9d4
// Entry: 8029f9d4
// Size: 80 bytes

undefined4 FUN_8029f9d4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_8001ffb4(0x2d0);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    *(code **)(param_2 + 0x308) = FUN_802a514c;
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

