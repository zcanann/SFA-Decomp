// Function: FUN_80213094
// Entry: 80213094
// Size: 148 bytes

int FUN_80213094(undefined4 param_1,int param_2)

{
  uint uVar1;
  int local_8 [2];
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      local_8[0] = 0;
      uVar1 = FUN_800138d4((short *)*DAT_803de9d4);
      if (uVar1 == 0) {
        FUN_80013900((short *)*DAT_803de9d4,(uint)local_8);
      }
      return local_8[0] + 1;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,5);
  }
  return 0;
}

