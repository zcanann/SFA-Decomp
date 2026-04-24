// Function: FUN_8029f6e4
// Entry: 8029f6e4
// Size: 752 bytes

undefined4 FUN_8029f6e4(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  undefined local_38 [2];
  undefined2 uStack54;
  float local_34;
  int local_30;
  float local_2c;
  float local_28 [2];
  longlong local_20;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dca50 + 0x68))(2);
  *(undefined *)(param_2 + 0x25f) = 0;
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) | 0x100000;
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) & 0xfffffffd;
  FUN_80035f00(param_1);
  iVar3 = *(int *)(iVar4 + 0x7f0);
  if (iVar3 == 0) {
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    uVar1 = 0;
  }
  else {
    if (*(char *)(param_2 + 0x27a) != '\0') {
      if (*(int *)(iVar4 + 0x6e8) == 0) {
        *(undefined **)(iVar4 + 0x6e8) = &DAT_803332b0;
      }
      FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)*(short *)(*(int *)(iVar4 + 0x6e8) + 2),0);
      FUN_8002fa48((double)FLOAT_803e7ea4,(double)FLOAT_803e7ea4,param_1,0);
    }
    if ((*(byte *)(iVar4 + 0x6ec) & 4) == 0) {
      dVar5 = (double)(**(code **)(**(int **)(iVar3 + 0x68) + 0x44))(iVar3,local_28);
      if (FLOAT_803e7ee0 < local_28[0]) {
        *(float *)(param_2 + 0x2a0) =
             (float)((double)FLOAT_803e7f6c * dVar5 + (double)FLOAT_803e7ef8);
      }
      else {
        *(float *)(param_2 + 0x2a0) = local_28[0];
      }
    }
    else {
      FUN_80030304((double)*(float *)(iVar3 + 0x98),param_1);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e7ea4;
    }
    if ((*(byte *)(iVar4 + 0x6ec) & 1) == 0) {
      if ((*(byte *)(iVar4 + 0x6ec) & 8) != 0) {
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x40))(iVar3,&local_34,local_38);
        *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x2000000;
        *(undefined2 *)(iVar4 + 0x4d6) = uStack54;
        local_20 = (longlong)(int)local_34;
        *(short *)(iVar4 + 0x4d4) = (short)(int)local_34;
        *(short *)(iVar4 + 0x4d2) = *(short *)(iVar4 + 0x4d4) / 2;
        *(short *)(iVar4 + 0x4d0) = *(short *)(iVar4 + 0x4d4) / 2;
      }
    }
    else {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x40))(iVar3,&local_2c,&local_30);
      iVar2 = (int)(FLOAT_803e7fac * local_2c);
      local_20 = (longlong)iVar2;
      if (iVar2 < 0) {
        iVar2 = -iVar2;
      }
      if (local_30 == 0) {
        FUN_8002ed6c(param_1,(int)*(short *)(*(int *)(iVar4 + 0x6e8) + 8),iVar2);
      }
      else {
        FUN_8002ed6c(param_1,(int)*(short *)(*(int *)(iVar4 + 0x6e8) + 10),iVar2);
      }
    }
    if ((*(byte *)(iVar4 + 0x6ec) & 1) != 0) {
      FUN_8002f52c(param_1,0,2,0);
      FUN_8002f52c(param_1,1,2,0);
    }
    iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x2c))(iVar3,param_1);
    if (iVar3 == 0) {
      uVar1 = 0;
    }
    else {
      *(undefined4 *)(param_2 + 0x308) = 0;
      uVar1 = 0x1a;
    }
  }
  return uVar1;
}

