// Function: FUN_8015e044
// Entry: 8015e044
// Size: 132 bytes

undefined4 FUN_8015e044(undefined4 param_1,int param_2)

{
  float fVar1;
  
  fVar1 = FLOAT_803e2dc8;
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) != '\0') {
      *(float *)(param_2 + 0x284) = FLOAT_803e2dc8;
      *(float *)(param_2 + 0x280) = fVar1;
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
    }
    if (*(char *)(param_2 + 0x346) != '\0') {
      return 6;
    }
  }
  return 0;
}

