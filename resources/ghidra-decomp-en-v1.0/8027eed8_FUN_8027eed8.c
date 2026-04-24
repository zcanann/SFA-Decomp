// Function: FUN_8027eed8
// Entry: 8027eed8
// Size: 68 bytes

undefined4 FUN_8027eed8(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (DAT_803de348 == (code *)0x0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (*DAT_803de348)(param_2,*(undefined4 *)(param_1 + 0x18));
  }
  return uVar1;
}

