// Function: FUN_80216a74
// Entry: 80216a74
// Size: 204 bytes

void FUN_80216a74(short *param_1,int param_2)

{
  int iVar1;
  
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  *(float *)(*(int *)(param_1 + 0x5c) + 8) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - DOUBLE_803e7520);
  param_1[0x7a] = 0;
  param_1[0x7b] = 1;
  param_1[0x7c] = 0;
  param_1[0x7d] = 1;
  iVar1 = *(int *)(param_1 + 0x26);
  iVar1 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(iVar1 + 8),(double)*(float *)(iVar1 + 0xc),
                     (double)*(float *)(iVar1 + 0x10),&DAT_803dcf08,1,0);
  if ((iVar1 != -1) && (iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar1 != 0)) {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0x10);
  }
  return;
}

