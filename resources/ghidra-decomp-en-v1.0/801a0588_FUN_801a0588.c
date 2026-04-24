// Function: FUN_801a0588
// Entry: 801a0588
// Size: 108 bytes

void FUN_801a0588(int param_1)

{
  int iVar1;
  
  if ((*(int *)(param_1 + 0xf4) != 0) && (iVar1 = FUN_8001ffb4(0x50), iVar1 == 0)) {
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
  }
  *(undefined4 *)(param_1 + 0xf4) = 0;
  return;
}

