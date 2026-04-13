// Function: FUN_801ba3cc
// Entry: 801ba3cc
// Size: 172 bytes

void FUN_801ba3cc(short *param_1,int param_2)

{
  int iVar1;
  
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         *(float *)(*(int *)(param_1 + 0x28) + 4) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e5848) /
         FLOAT_803e5840);
  }
  *(float *)(*(int *)(param_1 + 0x5c) + 0x10) = FLOAT_803e5844;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x810;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

