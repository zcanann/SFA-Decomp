// Function: FUN_801beeac
// Entry: 801beeac
// Size: 324 bytes

void FUN_801beeac(int param_1)

{
  char in_r8;
  undefined auStack_28 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b9ec(param_1);
    FUN_80038524(param_1,1,&local_1c,&local_18,&local_14,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x4bd,auStack_28,0x200001,0xffffffff,0);
    FUN_80038524(param_1,0,&local_1c,&local_18,&local_14,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x4bd,auStack_28,0x200001,0xffffffff,0);
    if ((DAT_803de810 != (int *)0x0) &&
       ((*(char *)(DAT_803de810 + 0xbe) != '\0' && (*(char *)(DAT_803de810 + 0x13) != '\0')))) {
      FUN_8001de4c((double)local_1c,(double)local_18,(double)local_14,DAT_803de810);
      FUN_80060630((int)DAT_803de810);
    }
  }
  return;
}

