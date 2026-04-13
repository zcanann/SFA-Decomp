// Function: FUN_80167f90
// Entry: 80167f90
// Size: 124 bytes

undefined4 FUN_80167f90(undefined4 param_1,int param_2)

{
  float fVar1;
  
  fVar1 = FLOAT_803e3cf8;
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) == '\0') {
      if (*(char *)(param_2 + 0x346) != '\0') {
        return 6;
      }
    }
    else {
      *(float *)(param_2 + 0x284) = FLOAT_803e3cf8;
      *(float *)(param_2 + 0x280) = fVar1;
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    }
  }
  return 0;
}

