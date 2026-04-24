// Function: FUN_8015b670
// Entry: 8015b670
// Size: 216 bytes

undefined4 FUN_8015b670(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      FUN_800376d8(0,3,param_1,0xe0000,param_1);
      if (*(int *)(param_1 + 0x4c) == 0) {
        FUN_8002cbc4(param_1);
        return 0;
      }
      return 4;
    }
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0xd);
    *(undefined4 *)(param_2 + 0x2d0) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(undefined *)(param_2 + 0x349) = 0;
    FUN_80035f00(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return 0;
}

