// Function: FUN_8017554c
// Entry: 8017554c
// Size: 128 bytes

uint FUN_8017554c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  fVar1 = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 0xc);
  fVar2 = *(float *)(param_2 + 0x10) - *(float *)(param_1 + 0x10);
  fVar3 = *(float *)(param_2 + 0x14) - *(float *)(param_1 + 0x14);
  dVar5 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  return ((uint)(byte)((dVar5 < (double)*(float *)(iVar4 + 0xc)) << 3) << 0x1c) >> 0x1f;
}

