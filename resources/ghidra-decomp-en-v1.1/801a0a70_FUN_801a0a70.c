// Function: FUN_801a0a70
// Entry: 801a0a70
// Size: 68 bytes

undefined4 FUN_801a0a70(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  
  uVar1 = FUN_80020078(0x4d);
  if (uVar1 != 0) {
    *(undefined *)(param_3 + 0x90) = 4;
  }
  return 0;
}

