// Function: FUN_8015bfac
// Entry: 8015bfac
// Size: 280 bytes

undefined4
FUN_8015bfac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  FUN_80033a34(param_9);
  if (*(byte *)(iVar2 + 0x406) < 0x33) {
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e39c0;
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 0xc;
  fVar1 = FLOAT_803e39ac;
  *(float *)(param_10 + 0x280) = FLOAT_803e39ac;
  *(float *)(param_10 + 0x284) = fVar1;
  if ((*(byte *)(iVar2 + 0x404) & 2) == 0) {
    *(float *)(param_10 + 0x280) = FLOAT_803e39c8 + *(float *)(param_9 + 0x98);
  }
  return 0;
}

