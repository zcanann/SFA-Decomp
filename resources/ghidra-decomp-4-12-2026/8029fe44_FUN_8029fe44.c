// Function: FUN_8029fe44
// Entry: 8029fe44
// Size: 752 bytes

undefined4
FUN_8029fe44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  undefined local_38 [2];
  undefined2 uStack_36;
  float local_34;
  int local_30;
  float local_2c;
  float local_28 [2];
  longlong local_20;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  (**(code **)(*DAT_803dd6d0 + 0x68))(2);
  *(undefined *)(param_10 + 0x25f) = 0;
  *(uint *)(param_10 + 4) = *(uint *)(param_10 + 4) | 0x100000;
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) & 0xfffffffd;
  FUN_80035ff8(param_9);
  iVar3 = *(int *)(iVar4 + 0x7f0);
  if (iVar3 == 0) {
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    uVar1 = 0;
  }
  else {
    if (*(char *)(param_10 + 0x27a) != '\0') {
      if (*(int *)(iVar4 + 0x6e8) == 0) {
        *(undefined **)(iVar4 + 0x6e8) = &DAT_80333f10;
      }
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)*(short *)(*(int *)(iVar4 + 0x6e8) + 2),0,param_12,param_13,param_14
                   ,param_15,param_16);
      param_2 = (double)FLOAT_803e8b3c;
      FUN_8002fb40(param_2,param_2);
    }
    if ((*(byte *)(iVar4 + 0x6ec) & 4) == 0) {
      dVar5 = (double)(**(code **)(**(int **)(iVar3 + 0x68) + 0x44))(iVar3,local_28);
      param_2 = (double)local_28[0];
      if ((double)FLOAT_803e8b78 < param_2) {
        param_2 = (double)FLOAT_803e8c04;
        *(float *)(param_10 + 0x2a0) = (float)(param_2 * dVar5 + (double)FLOAT_803e8b90);
      }
      else {
        *(float *)(param_10 + 0x2a0) = local_28[0];
      }
    }
    else {
      FUN_800303fc((double)*(float *)(iVar3 + 0x98),param_9);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8b3c;
    }
    if ((*(byte *)(iVar4 + 0x6ec) & 1) == 0) {
      if ((*(byte *)(iVar4 + 0x6ec) & 8) != 0) {
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x40))(iVar3,&local_34,local_38);
        *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x2000000;
        *(undefined2 *)(iVar4 + 0x4d6) = uStack_36;
        local_20 = (longlong)(int)local_34;
        *(short *)(iVar4 + 0x4d4) = (short)(int)local_34;
        *(short *)(iVar4 + 0x4d2) = *(short *)(iVar4 + 0x4d4) / 2;
        *(short *)(iVar4 + 0x4d0) = *(short *)(iVar4 + 0x4d4) / 2;
      }
    }
    else {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x40))(iVar3,&local_2c,&local_30);
      dVar5 = (double)FLOAT_803e8c44;
      iVar2 = (int)(dVar5 * (double)local_2c);
      local_20 = (longlong)iVar2;
      if (iVar2 < 0) {
        iVar2 = -iVar2;
      }
      if (local_30 == 0) {
        FUN_8002ee64(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                     (int)*(short *)(*(int *)(iVar4 + 0x6e8) + 8),(short)iVar2);
      }
      else {
        FUN_8002ee64(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                     (int)*(short *)(*(int *)(iVar4 + 0x6e8) + 10),(short)iVar2);
      }
    }
    if ((*(byte *)(iVar4 + 0x6ec) & 1) != 0) {
      FUN_8002f624(param_9,0,2,0);
      FUN_8002f624(param_9,1,2,0);
    }
    iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x2c))(iVar3,param_9);
    if (iVar3 == 0) {
      uVar1 = 0;
    }
    else {
      *(undefined4 *)(param_10 + 0x308) = 0;
      uVar1 = 0x1a;
    }
  }
  return uVar1;
}

