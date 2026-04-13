// Function: FUN_80224284
// Entry: 80224284
// Size: 188 bytes

undefined4 FUN_80224284(undefined2 *param_1,int param_2)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *(float *)(param_1 + 0x12) =
       FLOAT_803dc078 * (*(float *)(iVar1 + 0xa18) - *(float *)(param_1 + 6));
  *(float *)(param_1 + 0x16) =
       FLOAT_803dc078 * (*(float *)(iVar1 + 0xa20) - *(float *)(param_1 + 10));
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar1 + 0xa18);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar1 + 0xa20);
  iVar1 = FUN_80021884();
  *param_1 = (short)iVar1;
  dVar2 = FUN_80293900((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                               *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
  FUN_8002f6cc(dVar2,(int)param_1,(float *)(param_2 + 0x2a0));
  return 0;
}

