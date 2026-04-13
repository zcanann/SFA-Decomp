// Function: FUN_801be2ac
// Entry: 801be2ac
// Size: 108 bytes

bool FUN_801be2ac(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
  }
  return *(char *)(param_2 + 0x346) != '\0';
}

