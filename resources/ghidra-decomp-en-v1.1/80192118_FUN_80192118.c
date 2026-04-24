// Function: FUN_80192118
// Entry: 80192118
// Size: 180 bytes

void FUN_80192118(int param_1)

{
  undefined auStack_18 [12];
  float local_c;
  float local_8;
  float local_4;
  
  if (*(short *)(param_1 + 0x46) == 0x79) {
    local_c = FLOAT_803e4b9c;
    local_8 = FLOAT_803e4ba0;
    local_4 = FLOAT_803e4b9c;
    FUN_800979c0((double)FLOAT_803e4ba4,(double)FLOAT_803e4ba8,(double)FLOAT_803e4ba8,
                 (double)FLOAT_803e4bac,param_1,5,5,2,0x19,(int)auStack_18,0);
  }
  else if (*(short *)(param_1 + 0x46) == 0x748) {
    local_c = FLOAT_803e4b9c;
    local_8 = FLOAT_803e4bb0;
    local_4 = FLOAT_803e4b9c;
    FUN_800979c0((double)FLOAT_803e4bb4,(double)FLOAT_803e4bb8,(double)FLOAT_803e4bb8,
                 (double)FLOAT_803e4bac,param_1,5,5,2,5,(int)auStack_18,0);
  }
  return;
}

