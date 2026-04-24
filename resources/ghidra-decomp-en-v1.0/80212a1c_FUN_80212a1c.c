// Function: FUN_80212a1c
// Entry: 80212a1c
// Size: 148 bytes

int FUN_80212a1c(undefined4 param_1,int param_2)

{
  int iVar1;
  int local_8 [2];
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      local_8[0] = 0;
      iVar1 = FUN_800138b4(*DAT_803ddd54);
      if (iVar1 == 0) {
        FUN_800138e0(*DAT_803ddd54,local_8);
      }
      return local_8[0] + 1;
    }
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,5);
  }
  return 0;
}

