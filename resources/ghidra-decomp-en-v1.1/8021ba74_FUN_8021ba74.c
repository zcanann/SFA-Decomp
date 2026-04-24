// Function: FUN_8021ba74
// Entry: 8021ba74
// Size: 180 bytes

/* WARNING: Removing unreachable block (ram,0x8021bb08) */
/* WARNING: Removing unreachable block (ram,0x8021ba84) */

void FUN_8021ba74(double param_1,int param_2)

{
  float *pfVar1;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  pfVar1 = (float *)FUN_80038498(param_2,0);
  local_2c = FLOAT_803e76d4;
  local_28 = FLOAT_803e76d8;
  local_24 = FLOAT_803e76d4;
  local_38[0] = 0;
  local_38[1] = 0;
  local_38[2] = 0;
  local_30 = (float)(param_1 / (double)*(float *)(*(int *)(param_2 + 0x50) + 4));
  FUN_80021fac((float *)&DAT_803ade28,local_38);
  FUN_800223a8((float *)&DAT_803ade28,pfVar1,(float *)&DAT_803ade28);
  FUN_8003ba48(&DAT_803ade28);
  return;
}

