// Function: FUN_80161468
// Entry: 80161468
// Size: 108 bytes

bool FUN_80161468(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,9);
  }
  return *(char *)(param_2 + 0x346) != '\0';
}

