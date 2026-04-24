// Function: FUN_802239a4
// Entry: 802239a4
// Size: 120 bytes

undefined4 FUN_802239a4(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      return 3;
    }
  }
  else {
    *(byte *)(*(int *)(param_1 + 0xb8) + 0xac0) = *(byte *)(*(int *)(param_1 + 0xb8) + 0xac0) & 0xfe
    ;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,3);
  }
  return 0;
}

