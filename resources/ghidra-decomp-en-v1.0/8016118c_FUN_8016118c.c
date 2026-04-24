// Function: FUN_8016118c
// Entry: 8016118c
// Size: 184 bytes

undefined4 FUN_8016118c(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,8);
    *(undefined4 *)(param_2 + 0x2d0) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(undefined *)(param_2 + 0x349) = 0;
    FUN_80035f00(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  if (*(char *)(param_1 + 0x36) == '\0') {
    if (*(int *)(param_1 + 0x4c) == 0) {
      FUN_8002cbc4(param_1);
      uVar1 = 0;
    }
    else {
      uVar1 = 6;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

