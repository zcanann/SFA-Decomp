// Function: FUN_80026ec4
// Entry: 80026ec4
// Size: 244 bytes

void FUN_80026ec4(int param_1,int param_2,float *param_3)

{
  double dVar1;
  float fVar2;
  short *psVar3;
  
  fVar2 = FLOAT_803df4e4;
  dVar1 = DOUBLE_803df4a0;
  psVar3 = (short *)(*(int *)(param_1 + 0x28) + param_2 * 6);
  if ((*(ushort *)(param_1 + 2) & 0x800) == 0) {
    *param_3 = (float)((double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000) - DOUBLE_803df4a0) *
               FLOAT_803df4e4;
    param_3[1] = (float)((double)CONCAT44(0x43300000,(int)psVar3[1] ^ 0x80000000) - dVar1) * fVar2;
    param_3[2] = (float)((double)CONCAT44(0x43300000,(int)psVar3[2] ^ 0x80000000) - dVar1) * fVar2;
  }
  else {
    *param_3 = (float)((double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000) - DOUBLE_803df4a0);
    param_3[1] = (float)((double)CONCAT44(0x43300000,(int)psVar3[1] ^ 0x80000000) - dVar1);
    param_3[2] = (float)((double)CONCAT44(0x43300000,(int)psVar3[2] ^ 0x80000000) - dVar1);
  }
  return;
}

