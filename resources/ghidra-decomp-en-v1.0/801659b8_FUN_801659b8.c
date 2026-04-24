// Function: FUN_801659b8
// Entry: 801659b8
// Size: 388 bytes

undefined4 FUN_801659b8(undefined2 *param_1,uint *param_2)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x5c) + 0x40c);
  *(undefined *)((int)param_2 + 0x34d) = 1;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(float *)(iVar1 + 0x60) = FLOAT_803e3004;
    FUN_80035f20();
    dVar2 = (double)FUN_80293464(*param_1);
    *(float *)(param_1 + 0x12) = (float)(-(double)*(float *)(iVar1 + 0x60) * dVar2);
    *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
    dVar2 = (double)FUN_8029397c(*param_1);
    *(float *)(param_1 + 0x16) = (float)(-(double)*(float *)(iVar1 + 0x60) * dVar2);
    *param_2 = *param_2 | 0x2004000;
    FUN_80030334((double)FLOAT_803e2fdc,param_1,0,0);
    *(float *)(iVar1 + 0x44) = FLOAT_803e2fdc;
  }
  FUN_80035df4(param_1,9,1,0xffffffff);
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6c) = 9;
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6d) = 1;
  FUN_8003393c(param_1);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,param_2 + 1);
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    if (*(char *)(iVar1 + 0x90) == '\x06') {
      if ((*(byte *)(iVar1 + 0x92) >> 2 & 1) == 0) {
        FUN_80166444(param_1,iVar1);
      }
      else {
        FUN_80165b3c(param_1,iVar1);
      }
    }
    else {
      FUN_80165c8c(param_1,iVar1);
    }
  }
  return 0;
}

