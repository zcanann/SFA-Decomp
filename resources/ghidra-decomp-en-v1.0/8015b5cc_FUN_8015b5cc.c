// Function: FUN_8015b5cc
// Entry: 8015b5cc
// Size: 72 bytes

undefined4 FUN_8015b5cc(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,2);
  }
  return 0;
}

