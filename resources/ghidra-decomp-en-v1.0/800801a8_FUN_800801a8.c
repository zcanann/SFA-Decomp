// Function: FUN_800801a8
// Entry: 800801a8
// Size: 64 bytes

undefined4 FUN_800801a8(float *param_1)

{
  float fVar1;
  
  fVar1 = FLOAT_803defa0;
  if ((*param_1 != FLOAT_803defa0) && (*param_1 = *param_1 - FLOAT_803db414, *param_1 <= fVar1)) {
    *param_1 = fVar1;
    return 1;
  }
  return 0;
}

