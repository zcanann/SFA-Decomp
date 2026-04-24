// Function: FUN_8015b524
// Entry: 8015b524
// Size: 168 bytes

undefined4 FUN_8015b524(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,3);
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    if (*(short *)(param_2 + 0x274) != 3) {
      return 8;
    }
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
  }
  return 0;
}

