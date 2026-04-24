// Function: FUN_8028b6d0
// Entry: 8028b6d0
// Size: 60 bytes

undefined4 FUN_8028b6d0(undefined4 param_1,uint param_2,uint param_3)

{
  undefined4 uVar1;
  
  if (param_2 < param_3) {
    FUN_8028afe4(param_2,param_3 - param_2);
    uVar1 = 0;
  }
  else {
    uVar1 = 0x700;
  }
  return uVar1;
}

