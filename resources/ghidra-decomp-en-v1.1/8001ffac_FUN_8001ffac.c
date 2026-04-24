// Function: FUN_8001ffac
// Entry: 8001ffac
// Size: 84 bytes

uint FUN_8001ffac(uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_80020078(param_1);
  if (uVar1 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = uVar1 - 1;
    FUN_800201ac(param_1,uVar1);
  }
  return uVar1;
}

