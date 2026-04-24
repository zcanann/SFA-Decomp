// Function: FUN_801a04f4
// Entry: 801a04f4
// Size: 68 bytes

undefined4 FUN_801a04f4(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(0x4d);
  if (iVar1 != 0) {
    *(undefined *)(param_3 + 0x90) = 4;
  }
  return 0;
}

