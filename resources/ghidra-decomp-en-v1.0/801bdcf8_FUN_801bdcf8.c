// Function: FUN_801bdcf8
// Entry: 801bdcf8
// Size: 108 bytes

bool FUN_801bdcf8(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
  }
  return *(char *)(param_2 + 0x346) != '\0';
}

