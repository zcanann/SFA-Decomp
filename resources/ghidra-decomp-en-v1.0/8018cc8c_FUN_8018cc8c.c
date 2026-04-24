// Function: FUN_8018cc8c
// Entry: 8018cc8c
// Size: 208 bytes

void FUN_8018cc8c(int param_1)

{
  float fVar1;
  short *psVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  psVar2 = (short *)FUN_8000faac();
  FUN_800d7a70(1);
  (**(code **)(*DAT_803dca4c + 8))(1,1);
  FUN_80030334((double)FLOAT_803e3d1c,param_1,0x8e,0);
  *pfVar3 = FLOAT_803e3d58;
  pfVar3[1] = *(float *)(psVar2 + 6);
  pfVar3[2] = *(float *)(psVar2 + 8);
  pfVar3[3] = *(float *)(psVar2 + 10);
  pfVar3[6] = (float)(int)*psVar2;
  pfVar3[7] = (float)(int)psVar2[1];
  fVar1 = FLOAT_803e3d2c;
  pfVar3[4] = FLOAT_803e3d2c;
  pfVar3[5] = fVar1;
  FUN_8001fe74(param_1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x400;
  return;
}

