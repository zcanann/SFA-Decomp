// Function: FUN_8018d208
// Entry: 8018d208
// Size: 208 bytes

void FUN_8018d208(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short *psVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  psVar2 = FUN_8000facc();
  FUN_800d7cfc(1);
  (**(code **)(*DAT_803dd6cc + 8))(1,1);
  FUN_8003042c((double)FLOAT_803e49b4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0x8e,0,param_12,param_13,param_14,param_15,param_16);
  *pfVar3 = FLOAT_803e49f0;
  pfVar3[1] = *(float *)(psVar2 + 6);
  pfVar3[2] = *(float *)(psVar2 + 8);
  pfVar3[3] = *(float *)(psVar2 + 10);
  pfVar3[6] = (float)(int)*psVar2;
  pfVar3[7] = (float)(int)psVar2[1];
  fVar1 = FLOAT_803e49c4;
  pfVar3[4] = FLOAT_803e49c4;
  pfVar3[5] = fVar1;
  FUN_8001ff38(param_9);
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x400;
  return;
}

