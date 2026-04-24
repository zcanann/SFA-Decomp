// Function: FUN_801f943c
// Entry: 801f943c
// Size: 784 bytes

undefined4 FUN_801f943c(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined auStack56 [12];
  undefined auStack44 [6];
  undefined2 local_26;
  float local_20;
  float local_1c;
  float local_18 [2];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 == 2) {
      *(undefined *)(iVar4 + 0x68) = 0;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      iVar3 = FUN_8000faac();
      FUN_80247754(iVar3 + 0xc,param_1 + 0xc,auStack56);
      FUN_80247794(auStack56,auStack56);
      FUN_80247778((double)FLOAT_803e6038,auStack56,auStack56);
      FUN_80247730(param_1 + 0xc,auStack56,param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(param_1 + 0x14);
      FUN_8009ab70((double)FLOAT_803e6038,param_1,1,1,0,0,0,0,0);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      if (*(short *)(param_1 + 0x46) == 0x783) {
        FUN_800200e8(0xd27,0);
      }
    }
  }
  iVar5 = FUN_8001ffb4(0xd27);
  if (iVar5 != 0) {
    if (*(short *)(param_1 + 0x46) == 0x783) {
      iVar5 = FUN_8001ffb4(0xe49);
      if (iVar5 == 0) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7ed,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7ed,auStack44,2,0xffffffff,0);
      }
      FUN_800969b0((double)FLOAT_803e603c,(double)FLOAT_803e6040,(double)FLOAT_803e6044,
                   (double)FLOAT_803e6048,(double)FLOAT_803e6038,param_1,iVar4,1);
      FUN_800969b0((double)FLOAT_803e603c,(double)FLOAT_803e6040,(double)FLOAT_803e604c,
                   (double)FLOAT_803e6048,(double)FLOAT_803e6050,param_1,iVar4 + 0x34,1);
    }
    else if ((*(short *)(param_1 + 0x46) == 0x784) && (*(char *)(iVar4 + 0x68) != '\0')) {
      FUN_800382f0(param_1,0,&local_20,&local_1c,local_18);
      fVar2 = *(float *)(param_1 + 8);
      local_20 = local_20 * fVar2;
      local_1c = local_1c * fVar2;
      local_18[0] = local_18[0] * fVar2;
      local_26 = 1;
      FUN_800972dc((double)FLOAT_803e6054,(double)FLOAT_803e6058,param_1,5,1,1,10,auStack44,0);
      FUN_800382f0(param_1,1,&local_20,&local_1c,local_18);
      fVar2 = *(float *)(param_1 + 8);
      local_20 = local_20 * fVar2;
      local_1c = local_1c * fVar2;
      local_18[0] = local_18[0] * fVar2;
      local_26 = 0;
      FUN_800972dc((double)FLOAT_803e6054,(double)FLOAT_803e6058,param_1,5,1,1,10,auStack44,0);
    }
  }
  return 0;
}

