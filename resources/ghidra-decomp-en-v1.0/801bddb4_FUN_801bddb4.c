// Function: FUN_801bddb4
// Entry: 801bddb4
// Size: 364 bytes

/* WARNING: Removing unreachable block (ram,0x801bde30) */

undefined4 FUN_801bddb4(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined auStack24 [2];
  undefined auStack22 [2];
  ushort local_14 [6];
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FLOAT_803ddb9c = FLOAT_803ddba0;
    uVar1 = FUN_8002b9ec();
    (**(code **)(*DAT_803dcab8 + 0x14))(param_1,uVar1,4,local_14,auStack22,auStack24);
    if (local_14[0] == 1) {
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e4c90,param_1,3,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else if (local_14[0] == 0) {
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e4c90,param_1,1,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else if (local_14[0] < 3) {
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e4c90,param_1,2,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e4c90,param_1,4,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(float *)(param_2 + 0x2a0) = FLOAT_803e4c94;
  }
  return 0;
}

