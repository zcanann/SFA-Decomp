// Function: FUN_8015e84c
// Entry: 8015e84c
// Size: 384 bytes

undefined4
FUN_8015e84c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int local_18;
  int local_14;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  iVar3 = -1;
  FUN_80035eec(param_9,10,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
  FUN_80033a34(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_8002e1f4(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      uVar2 = *(uint *)(iVar1 + local_18 * 4);
      if ((uVar2 != param_9) && (*(short *)(uVar2 + 0x46) == 0x306)) {
        iVar3 = **(int **)(uVar2 + 0x68);
        (**(code **)(iVar3 + 0x24))(uVar2,0x81,0);
      }
    }
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3a70;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,iVar3,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    iVar4 = *(int *)(iVar4 + 0x40c);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
    *(byte *)(iVar4 + 8) = *(byte *)(iVar4 + 8) | 1;
    FUN_8000bb38(param_9,0x266);
  }
  return 0;
}

