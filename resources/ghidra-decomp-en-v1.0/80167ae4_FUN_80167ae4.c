// Function: FUN_80167ae4
// Entry: 80167ae4
// Size: 124 bytes

undefined4 FUN_80167ae4(undefined4 param_1,int param_2)

{
  float fVar1;
  
  fVar1 = FLOAT_803e3060;
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) == '\0') {
      if (*(char *)(param_2 + 0x346) != '\0') {
        return 6;
      }
    }
    else {
      *(float *)(param_2 + 0x284) = FLOAT_803e3060;
      *(float *)(param_2 + 0x280) = fVar1;
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
    }
  }
  return 0;
}

