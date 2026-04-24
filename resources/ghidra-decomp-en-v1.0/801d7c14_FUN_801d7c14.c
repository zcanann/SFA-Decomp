// Function: FUN_801d7c14
// Entry: 801d7c14
// Size: 128 bytes

undefined4 FUN_801d7c14(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_3 + iVar1 + 0x81) == '\0') {
      FUN_801d80f4(*(undefined4 *)(param_1 + 0xb8));
    }
  }
  FUN_801d7c94(param_1,*(undefined4 *)(param_1 + 0xb8));
  return 0;
}

