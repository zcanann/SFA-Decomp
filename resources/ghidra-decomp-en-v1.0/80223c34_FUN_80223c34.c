// Function: FUN_80223c34
// Entry: 80223c34
// Size: 188 bytes

undefined4 FUN_80223c34(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined2 uVar2;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *(float *)(param_1 + 0x12) =
       FLOAT_803db418 * (*(float *)(iVar1 + 0xa18) - *(float *)(param_1 + 6));
  *(float *)(param_1 + 0x16) =
       FLOAT_803db418 * (*(float *)(iVar1 + 0xa20) - *(float *)(param_1 + 10));
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 0xa18);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0xa20);
  uVar2 = FUN_800217c0(-(double)*(float *)(iVar1 + 0xa24),-(double)*(float *)(iVar1 + 0xa2c));
  *param_1 = uVar2;
  FUN_802931a0((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                       *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
  FUN_8002f5d4(param_1,param_2 + 0x2a0);
  return 0;
}

