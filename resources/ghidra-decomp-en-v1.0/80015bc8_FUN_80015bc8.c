// Function: FUN_80015bc8
// Entry: 80015bc8
// Size: 40 bytes

undefined4 FUN_80015bc8(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if (((param_1 == 0x20) || (param_1 == 0x3000)) || (param_1 == 0x303f)) {
    uVar1 = 1;
  }
  return uVar1;
}

