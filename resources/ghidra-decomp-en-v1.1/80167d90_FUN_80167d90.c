// Function: FUN_80167d90
// Entry: 80167d90
// Size: 72 bytes

undefined4 FUN_80167d90(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
  }
  return 0;
}

