// Function: FUN_8023fbf4
// Entry: 8023fbf4
// Size: 152 bytes

void FUN_8023fbf4(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0x22) = *(undefined *)(param_2 + 0x1b);
  *(undefined *)(iVar1 + 0x24) = 0xff;
  *(undefined *)(iVar1 + 0x25) = 0xf;
  *(undefined *)(iVar1 + 0x27) = 5;
  *(undefined *)(iVar1 + 0x23) = 3;
  *(undefined *)(iVar1 + 0x24) = 3;
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80030334((double)FLOAT_803e75ac,param_1,4,0);
  *(undefined4 *)(iVar1 + 0x14) = DAT_8032c280;
  *(float *)(param_1 + 0x98) = FLOAT_803e75b0;
  FUN_80035960(param_1,4);
  return;
}

