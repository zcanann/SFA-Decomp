// Function: FUN_8019c50c
// Entry: 8019c50c
// Size: 88 bytes

void FUN_8019c50c(int param_1)

{
  char in_r8;
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e4130);
    FUN_80114dec(param_1,uVar1,0);
  }
  return;
}

