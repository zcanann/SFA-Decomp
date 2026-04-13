// Function: FUN_801be318
// Entry: 801be318
// Size: 80 bytes

undefined4 FUN_801be318(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    *(undefined *)(param_2 + 0x27a) = 1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
  }
  return 0;
}

