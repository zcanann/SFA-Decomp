// Function: FUN_80287e2c
// Entry: 80287e2c
// Size: 48 bytes

undefined4 FUN_80287e2c(int param_1,uint param_2)

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

