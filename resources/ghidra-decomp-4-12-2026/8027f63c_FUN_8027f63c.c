// Function: FUN_8027f63c
// Entry: 8027f63c
// Size: 68 bytes

undefined4 FUN_8027f63c(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (DAT_803defc8 == (code *)0x0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (*DAT_803defc8)(param_2,*(undefined4 *)(param_1 + 0x18));
  }
  return uVar1;
}

