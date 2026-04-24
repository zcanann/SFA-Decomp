// Function: FUN_80156950
// Entry: 80156950
// Size: 244 bytes

void FUN_80156950(int param_1,int param_2)

{
  short sVar1;
  
  sVar1 = *(short *)(param_1 + 0xa0);
  if (sVar1 == 7) {
    if (*(short *)(param_2 + 0x2f8) != 0) {
      if (FLOAT_803e2af8 <= *(float *)(param_1 + 0x98)) {
        FUN_8000bb18(param_1,0x24c);
      }
      else {
        FUN_8000bb18(param_1,0x24d);
      }
    }
  }
  else if (sVar1 < 7) {
    if (sVar1 == 5) {
      if (*(short *)(param_2 + 0x2f8) != 0) {
        FUN_8000bb18(param_1,0x24d);
      }
    }
    else if ((4 < sVar1) && (*(short *)(param_2 + 0x2f8) != 0)) {
      FUN_8000bb18(param_1,0x24d);
    }
  }
  else if ((sVar1 < 9) && (*(short *)(param_2 + 0x2f8) != 0)) {
    if (FLOAT_803e2afc <= *(float *)(param_1 + 0x98)) {
      if (FLOAT_803e2b00 <= *(float *)(param_1 + 0x98)) {
        FUN_8000bb18(param_1,0x24c);
      }
      else {
        FUN_8000bb18(param_1,0x24e);
      }
    }
    else {
      FUN_8000bb18(param_1,0x24b);
    }
  }
  return;
}

