// Function: FUN_801fabbc
// Entry: 801fabbc
// Size: 168 bytes

void FUN_801fabbc(int param_1,int param_2)

{
  undefined uVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0xb8);
  *psVar2 = *(short *)(param_2 + 0x1e);
  psVar2[1] = 0x19;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  if (2 < *(short *)(param_2 + 0x1a)) {
    *(undefined2 *)(param_2 + 0x1a) = 2;
  }
  if (1 < *(short *)(param_2 + 0x1c)) {
    *(float *)(param_1 + 8) =
         *(float *)(param_1 + 8) *
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                DOUBLE_803e60c8);
  }
  FUN_8002b884(param_1,(int)*(short *)(param_2 + 0x1a));
  uVar1 = FUN_8001ffb4((int)*psVar2);
  *(undefined *)((int)psVar2 + 5) = uVar1;
  return;
}

