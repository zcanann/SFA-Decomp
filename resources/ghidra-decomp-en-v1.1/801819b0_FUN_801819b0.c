// Function: FUN_801819b0
// Entry: 801819b0
// Size: 120 bytes

void FUN_801819b0(int param_1,int param_2)

{
  double dVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  fVar2 = FLOAT_803e45c0;
  dVar1 = DOUBLE_803e45b0;
  *(float *)(param_1 + 8) =
       *(float *)(*(int *)(param_1 + 0x50) + 4) *
       ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x18)) - DOUBLE_803e45b0) /
       FLOAT_803e45c0);
  *(undefined *)(iVar3 + 0x108) = 1;
  *(float *)(iVar3 + 0x110) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - dVar1) / fVar2;
  return;
}

