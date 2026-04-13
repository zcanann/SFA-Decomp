// Function: FUN_801d3e2c
// Entry: 801d3e2c
// Size: 1520 bytes

void FUN_801d3e2c(double param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  float fVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  undefined2 *puVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined4 uStack_28;
  uint uStack_24;
  uint local_20 [2];
  longlong local_18;
  
  puVar8 = *(undefined2 **)(param_9 + 0x5c);
  if ((*(byte *)(puVar8 + 0x158) >> 6 & 1) != 0) {
    while (iVar5 = FUN_800375e4((int)param_9,local_20,&uStack_24,(uint *)0x0), iVar5 != 0) {
      if (local_20[0] == 0x7000b) {
        FUN_80020000(0x66c);
        FUN_8000bb38((uint)param_9,0xa7);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
        iVar5 = 0;
        do {
          FUN_80097568((double)FLOAT_803e6048,(double)FLOAT_803e6050,param_9,5,7,1,0x3c,0,0);
          in_r7 = 0xffffffff;
          in_r8 = 0;
          in_r9 = *DAT_803dd708;
          (**(code **)(in_r9 + 8))(param_9,0x3f3,0,4);
          iVar5 = iVar5 + 1;
        } while (iVar5 < 10);
        FUN_8001dc30((double)FLOAT_803e6044,*(int *)(puVar8 + 0x138),'\0');
        *(float *)(puVar8 + 0x152) = FLOAT_803e6054;
        param_9[3] = param_9[3] | 0x4000;
        param_1 = (double)FUN_80035ff8((int)param_9);
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0xbf;
      }
    }
    if ((*(byte *)(puVar8 + 0x158) >> 6 & 1) != 0) {
      return;
    }
  }
  dVar9 = (double)FLOAT_803e602c;
  if ((double)*(float *)(puVar8 + 0x152) == dVar9) {
    dVar11 = (double)*(float *)(puVar8 + 0x13a);
    dVar10 = (double)FLOAT_803e6058;
    if (dVar11 < dVar10) {
      in_r7 = (uint)-(float)((double)FLOAT_803e6060 * dVar11 - (double)FLOAT_803e605c);
      local_18 = (longlong)(int)in_r7;
      in_r7 = in_r7 & 0xff;
      dVar9 = (double)(float)(DOUBLE_803e6070 * (double)(float)(dVar10 - dVar11) + DOUBLE_803e6068);
      in_r8 = 0;
      in_r9 = 0;
      param_3 = DOUBLE_803e6070;
      param_1 = (double)FUN_80097568((double)FLOAT_803e6048,dVar9,param_9,5,7,1,in_r7,0,0);
    }
    FUN_80036974((int)param_9,&uStack_28,(int *)0x0,(uint *)0x0);
    iVar5 = **(int **)(param_9 + 0x2a);
    if (-1 < *(char *)(puVar8 + 0x158)) {
      *(float *)(puVar8 + 0x142) = *(float *)(puVar8 + 0x142) - FLOAT_803dc074;
      if (*(float *)(puVar8 + 0x142) < FLOAT_803e602c) {
        *(float *)(puVar8 + 0x142) = FLOAT_803e602c;
      }
      *(float *)(puVar8 + 0x150) = *(float *)(puVar8 + 0x150) - FLOAT_803dc074;
      if (*(float *)(puVar8 + 0x150) < FLOAT_803e602c) {
        *(float *)(puVar8 + 0x150) = FLOAT_803e602c;
      }
      *param_9 = *param_9 + puVar8[0x157];
      *(float *)(param_9 + 0x14) = FLOAT_803e6078 * FLOAT_803dc074 + *(float *)(param_9 + 0x14);
      if (*(float *)(param_9 + 0x14) < FLOAT_803e607c) {
        *(float *)(param_9 + 0x14) = FLOAT_803e607c;
      }
      if (FLOAT_803e602c < *(float *)(param_9 + 0x14)) {
        *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e6080;
      }
      if (*(float *)(param_9 + 0x14) < FLOAT_803e602c) {
        FUN_80036018((int)param_9);
      }
      FUN_801d3b8c((int)param_9,(int)puVar8);
      uVar6 = FUN_80022264(0,100);
      if (((int)uVar6 < 5) && (*(float *)(puVar8 + 0x142) <= FLOAT_803e602c)) {
        FUN_801d39c4((int)param_9,(int)puVar8);
      }
      fVar1 = *(float *)(puVar8 + 0x14c) - FLOAT_803dc074;
      *(float *)(puVar8 + 0x14c) = fVar1;
      fVar4 = FLOAT_803e6080;
      fVar3 = FLOAT_803e602c;
      if (FLOAT_803e602c < fVar1) {
        *(float *)(puVar8 + 0x13e) =
             FLOAT_803e6084 * (*(float *)(puVar8 + 0x14e) - *(float *)(puVar8 + 0x13e)) *
             FLOAT_803dc074 + *(float *)(puVar8 + 0x13e);
      }
      else {
        *(float *)(puVar8 + 0x148) = *(float *)(puVar8 + 0x148) * FLOAT_803e6080;
        *(float *)(puVar8 + 0x14a) = *(float *)(puVar8 + 0x14a) * fVar4;
        *(float *)(puVar8 + 0x14c) = fVar3;
      }
      *(float *)(param_9 + 0x12) =
           *(float *)(puVar8 + 0x148) * *(float *)(puVar8 + 0x13e) + *(float *)(puVar8 + 0x144);
      *(float *)(param_9 + 0x16) =
           *(float *)(puVar8 + 0x14a) * *(float *)(puVar8 + 0x13e) + *(float *)(puVar8 + 0x146);
      dVar9 = (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074);
      param_3 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
      FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),dVar9,param_3,(int)param_9)
      ;
      (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_9,puVar8 + 4);
      (**(code **)(*DAT_803dd728 + 0x14))(param_9,puVar8 + 4);
      param_1 = (double)(**(code **)(*DAT_803dd728 + 0x18))
                                  ((double)FLOAT_803dc074,param_9,puVar8 + 4);
      if ((((iVar5 != 0) && (sVar2 = *(short *)(iVar5 + 0x46), sVar2 != 0x36d)) && (sVar2 != 0x198))
         && (sVar2 != 0x63c)) {
        FUN_8000bb38((uint)param_9,0x59);
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0x7f | 0x80;
        param_1 = (double)*(float *)(puVar8 + 0x13a);
        if ((double)FLOAT_803e6058 < param_1) {
          *(float *)(puVar8 + 0x13a) = FLOAT_803e6058;
        }
      }
      if ((*(byte *)(puVar8 + 0x134) & 0x11) != 0) {
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0x7f | 0x80;
        param_1 = (double)*(float *)(puVar8 + 0x13a);
        if ((double)FLOAT_803e6058 < param_1) {
          *(float *)(puVar8 + 0x13a) = FLOAT_803e6058;
        }
      }
    }
    iVar7 = FUN_8002bac4();
    if (iVar5 == iVar7) {
      *puVar8 = 0x18e;
      FUN_800379bc(param_1,dVar9,param_3,dVar10,dVar11,param_6,param_7,param_8,iVar5,0x7000a,
                   (uint)param_9,(uint)puVar8,in_r7,in_r8,in_r9,in_r10);
      *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0xbf | 0x40;
    }
    else {
      fVar1 = *(float *)(puVar8 + 0x13a) - FLOAT_803dc074;
      *(float *)(puVar8 + 0x13a) = fVar1;
      if (fVar1 <= FLOAT_803e602c) {
        FUN_8000bb38((uint)param_9,0xa2);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
        iVar5 = 0;
        do {
          FUN_80097568((double)FLOAT_803e6048,(double)FLOAT_803e6050,param_9,5,7,1,0x3c,0,0);
          (**(code **)(*DAT_803dd708 + 8))(param_9,0x3f3,0,4,0xffffffff,0);
          iVar5 = iVar5 + 1;
        } while (iVar5 < 10);
        FUN_8001dc30((double)FLOAT_803e6044,*(int *)(puVar8 + 0x138),'\0');
        *(float *)(puVar8 + 0x152) = FLOAT_803e6054;
        param_9[3] = param_9[3] | 0x4000;
        FUN_80035ff8((int)param_9);
      }
    }
  }
  else {
    *param_9 = *param_9 + (ushort)DAT_803dc070 * 0x40;
    fVar1 = *(float *)(puVar8 + 0x152);
    *(float *)(puVar8 + 0x152) = (float)((double)fVar1 - (double)FLOAT_803dc074);
    if ((double)*(float *)(puVar8 + 0x152) <= dVar9) {
      FUN_8002cc9c((double)fVar1,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9)
      ;
    }
  }
  return;
}

