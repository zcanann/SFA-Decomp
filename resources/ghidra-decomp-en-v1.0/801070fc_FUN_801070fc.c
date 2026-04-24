// Function: FUN_801070fc
// Entry: 801070fc
// Size: 896 bytes

void FUN_801070fc(short *param_1)

{
  char cVar2;
  uint uVar1;
  int iVar3;
  int iVar4;
  int iVar5;
  float local_38;
  float local_34;
  undefined auStack48 [4];
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [4];
  
  if (*(char *)(DAT_803dd538 + 0x6f) == '\0') {
    if (*DAT_803dd538 != *(int *)(param_1 + 0x18)) {
      iVar4 = 0;
      for (iVar5 = 0; iVar5 < DAT_803dd538[0x6c]; iVar5 = iVar5 + 1) {
        FUN_8000e0a0((double)*(float *)((int)DAT_803dd538 + iVar4 + 0x1c),
                     (double)*(float *)((int)DAT_803dd538 + iVar4 + 0x6c),
                     (double)*(float *)((int)DAT_803dd538 + iVar4 + 0xbc),
                     (int)DAT_803dd538 + iVar4 + 0x1c,(int)DAT_803dd538 + iVar4 + 0x6c,
                     (int)DAT_803dd538 + iVar4 + 0xbc,*DAT_803dd538);
        iVar4 = iVar4 + 4;
      }
      iVar4 = 0;
      for (iVar5 = 0; iVar5 < DAT_803dd538[0x6c]; iVar5 = iVar5 + 1) {
        FUN_8000e034((double)*(float *)((int)DAT_803dd538 + iVar4 + 0x1c),
                     (double)*(float *)((int)DAT_803dd538 + iVar4 + 0x6c),
                     (double)*(float *)((int)DAT_803dd538 + iVar4 + 0xbc),
                     (int)DAT_803dd538 + iVar4 + 0x1c,(int)DAT_803dd538 + iVar4 + 0x6c,
                     (int)DAT_803dd538 + iVar4 + 0xbc,*(undefined4 *)(param_1 + 0x18));
        iVar4 = iVar4 + 4;
      }
      *DAT_803dd538 = *(int *)(param_1 + 0x18);
    }
    iVar5 = *(int *)(param_1 + 0x52);
    local_24 = *(undefined4 *)(param_1 + 8);
    cVar2 = FUN_80106654(&local_28,&local_24,local_20,iVar5,param_1);
    *(undefined4 *)(param_1 + 6) = local_28;
    *(undefined4 *)(param_1 + 10) = local_20[0];
    iVar4 = (**(code **)(*DAT_803dca50 + 0x18))();
    FUN_8000e0a0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                 (double)*(float *)(param_1 + 10),param_1 + 0xc,param_1 + 0xe,param_1 + 0x10,
                 *(undefined4 *)(param_1 + 0x18));
    (**(code **)(**(int **)(iVar4 + 4) + 0x1c))
              ((double)FLOAT_803e1758,(double)FLOAT_803e175c,param_1,iVar5);
    (**(code **)(**(int **)(iVar4 + 4) + 0x24))(param_1,1,3,DAT_803dd538 + 5,DAT_803dd538 + 6);
    if ((param_1[0x50] != 0) || (*(char *)(param_1 + 0xa1) != '\0')) {
      DAT_803dd538[0x47] = (int)((float)DAT_803dd538[0x47] + FLOAT_803db414);
    }
    if (FLOAT_803e1740 < (float)DAT_803dd538[0x47]) {
      cVar2 = FUN_80103708(param_1,iVar5,param_1 + 0xc,param_1 + 1);
      if (cVar2 == '\x01') {
        FUN_80103660(1);
      }
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      cVar2 = '\x01';
    }
    (**(code **)(*DAT_803dca50 + 0x38))
              ((double)FLOAT_803e1740,param_1,&local_2c,auStack48,&local_34,&local_38,0);
    uVar1 = FUN_800217c0((double)local_2c,(double)local_34);
    iVar3 = (0x8000 - (uVar1 & 0xffff)) - ((int)*param_1 & 0xffffU);
    if (0x8000 < iVar3) {
      iVar3 = iVar3 + -0xffff;
    }
    if (iVar3 < -0x8000) {
      iVar3 = iVar3 + 0xffff;
    }
    *param_1 = *param_1 + (short)iVar3;
    (**(code **)(**(int **)(iVar4 + 4) + 0x18))
              ((double)*(float *)(iVar5 + 0x1c),(double)local_38,param_1);
    if (cVar2 != '\0') {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
    }
    FUN_80106f78(param_1,iVar5);
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

