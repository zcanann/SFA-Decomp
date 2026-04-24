// Function: FUN_800066e0
// Entry: 800066e0
// Size: 100 bytes

undefined4 FUN_800066e0(undefined4 param_1,undefined4 param_2,uint param_3)

{
  undefined4 uVar1;
  
  uVar1 = FUN_80023cc8(0x28,0xffffffff,0);
  FUN_8001f71c(uVar1,0xc,(param_3 & 0xffff) * 0x28,0x28);
  FUN_80023800(uVar1);
  return 0;
}

