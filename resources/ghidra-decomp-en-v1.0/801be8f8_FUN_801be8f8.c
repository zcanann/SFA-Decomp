// Function: FUN_801be8f8
// Entry: 801be8f8
// Size: 324 bytes

void FUN_801be8f8(int param_1)

{
  char in_r8;
  undefined auStack40 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b8f4((double)FLOAT_803e4cb8);
    FUN_8003842c(param_1,1,&local_1c,&local_18,&local_14,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4bd,auStack40,0x200001,0xffffffff,0);
    FUN_8003842c(param_1,0,&local_1c,&local_18,&local_14,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4bd,auStack40,0x200001,0xffffffff,0);
    if ((DAT_803ddb90 != 0) &&
       ((*(char *)(DAT_803ddb90 + 0x2f8) != '\0' && (*(char *)(DAT_803ddb90 + 0x4c) != '\0')))) {
      FUN_8001dd88((double)local_1c,(double)local_18,(double)local_14);
      FUN_800604b4(DAT_803ddb90);
    }
  }
  return;
}

