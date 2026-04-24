// Function: FUN_801784a4
// Entry: 801784a4
// Size: 76 bytes

void FUN_801784a4(int param_1,int param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
              DOUBLE_803e42a8);
  FUN_80035a58(param_1,1);
  return;
}

