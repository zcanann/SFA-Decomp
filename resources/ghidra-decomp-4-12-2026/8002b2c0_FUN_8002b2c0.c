// Function: FUN_8002b2c0
// Entry: 8002b2c0
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x8002b35c) */
/* WARNING: Removing unreachable block (ram,0x8002b2d0) */

void FUN_8002b2c0(ushort *param_1,float *param_2,float *param_3,char param_4)

{
  double in_f31;
  float afStack_68 [18];
  
  if (param_4 != '\0') {
    in_f31 = (double)*(float *)(param_1 + 4);
    *(float *)(param_1 + 4) = FLOAT_803df510;
  }
  FUN_8002b554(param_1,afStack_68,'\0');
  FUN_80247bf8(afStack_68,param_2,param_3);
  if (param_4 != '\0') {
    *(float *)(param_1 + 4) = (float)in_f31;
  }
  *param_3 = *param_3 + FLOAT_803dda58;
  param_3[2] = param_3[2] + FLOAT_803dda5c;
  return;
}

