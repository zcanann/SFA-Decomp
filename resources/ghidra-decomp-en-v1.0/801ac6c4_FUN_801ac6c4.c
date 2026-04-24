// Function: FUN_801ac6c4
// Entry: 801ac6c4
// Size: 132 bytes

undefined4 FUN_801ac6c4(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  *(uint *)(*(int *)(param_1 + 0xb8) + 4) = *(uint *)(*(int *)(param_1 + 0xb8) + 4) | 1;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_3 + iVar1 + 0x81) == '\x02') {
      FUN_800200e8(0x378,0);
      FUN_800200e8(0x3b9,0);
    }
  }
  return 0;
}

