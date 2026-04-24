// Function: FUN_80191b9c
// Entry: 80191b9c
// Size: 180 bytes

void FUN_80191b9c(int param_1)

{
  undefined auStack24 [12];
  float local_c;
  float local_8;
  float local_4;
  
  if (*(short *)(param_1 + 0x46) == 0x79) {
    local_c = FLOAT_803e3f04;
    local_8 = FLOAT_803e3f08;
    local_4 = FLOAT_803e3f04;
    FUN_80097734((double)FLOAT_803e3f0c,(double)FLOAT_803e3f10,(double)FLOAT_803e3f10,
                 (double)FLOAT_803e3f14,param_1,5,5,2,0x19,auStack24,0);
  }
  else if (*(short *)(param_1 + 0x46) == 0x748) {
    local_c = FLOAT_803e3f04;
    local_8 = FLOAT_803e3f18;
    local_4 = FLOAT_803e3f04;
    FUN_80097734((double)FLOAT_803e3f1c,(double)FLOAT_803e3f20,(double)FLOAT_803e3f20,
                 (double)FLOAT_803e3f14,param_1,5,5,2,5,auStack24,0);
  }
  return;
}

