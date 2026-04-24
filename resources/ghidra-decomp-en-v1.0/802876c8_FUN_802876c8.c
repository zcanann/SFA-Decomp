// Function: FUN_802876c8
// Entry: 802876c8
// Size: 48 bytes

undefined4 FUN_802876c8(int param_1,uint param_2)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if (param_2 < 0x881) {
    *(uint *)(param_1 + 0xc) = param_2;
    if (*(uint *)(param_1 + 8) < param_2) {
      *(uint *)(param_1 + 8) = param_2;
    }
  }
  else {
    uVar1 = 0x301;
  }
  return uVar1;
}

