// Function: FUN_80210980
// Entry: 80210980
// Size: 212 bytes

undefined4 FUN_80210980(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  *(byte *)(*(int *)(param_1 + 0xb8) + 9) = *(byte *)(*(int *)(param_1 + 0xb8) + 9) | 1;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    if (*(char *)(param_3 + iVar2 + 0x81) == '\x01') {
      FUN_800200e8(0xdca,1);
      FUN_800200e8(0x458,0);
      FUN_80042f78(0xc);
      FUN_8004350c(0,0,1);
      uVar1 = FUN_800481b0(0xc);
      FUN_80043560(uVar1,0);
      (**(code **)(*DAT_803dcaac + 0x50))(0xc,1,1);
    }
  }
  return 0;
}

