// Function: FUN_802a1e2c
// Entry: 802a1e2c
// Size: 1500 bytes

/* WARNING: Removing unreachable block (ram,0x802a23e4) */
/* WARNING: Removing unreachable block (ram,0x802a23dc) */
/* WARNING: Removing unreachable block (ram,0x802a1e44) */
/* WARNING: Removing unreachable block (ram,0x802a1e3c) */

undefined4
FUN_802a1e2c(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,int param_16)

{
  char cVar1;
  undefined4 uVar2;
  short sVar3;
  float fVar4;
  int iVar5;
  ushort uVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  float afStack_38 [3];
  
  iVar7 = *(int *)(param_9 + 0xb8);
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    FUN_80035f84(param_9);
    FLOAT_803df118 = FLOAT_803e8b3c;
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x35,1,param_12,param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8bb8;
    *(undefined4 *)(iVar7 + 0x500) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar7 + 0x76c);
    FUN_802abd04(param_9,iVar7,5);
  }
  if (FLOAT_803e8c38 < *(float *)(iVar7 + 0x838)) {
    FUN_802abd04(param_9,iVar7,5);
    FUN_802aef9c(param_9,iVar7);
    param_10[0xc2] = (uint)FUN_802a58ac;
    return 2;
  }
  param_10[1] = param_10[1] | 0x100000;
  param_10[1] = param_10[1] | 0x8000000;
  *param_10 = *param_10 | 0x200000;
  sVar3 = *(short *)(param_9 + 0xa0);
  if (sVar3 == 0x36) {
LAB_802a1f74:
    dVar8 = (double)(FLOAT_803e8b70 * -FLOAT_803df118);
    if ((param_10[0xc5] & 1) != 0) {
      FUN_8000bb38(param_9,0x210);
    }
    dVar11 = (double)(*(float *)(param_9 + 0x10) - (FLOAT_803e8ca8 + *(float *)(iVar7 + 0x4ec)));
    if (dVar11 < (double)FLOAT_803e8b3c) {
      dVar11 = (double)FLOAT_803e8b3c;
    }
    if (dVar8 <= dVar11) {
      if ((double)FLOAT_803e8cac < (double)*(float *)(param_9 + 0x28)) {
        *(float *)(param_9 + 0x28) =
             -(float)((double)FLOAT_803e8c04 * param_1 - (double)*(float *)(param_9 + 0x28));
      }
      if (*(float *)(param_9 + 0x28) < FLOAT_803e8cac) {
        *(float *)(param_9 + 0x28) = FLOAT_803e8cac;
      }
      if (*(float *)(param_9 + 0x28) < FLOAT_803df118) {
        FLOAT_803df118 = *(float *)(param_9 + 0x28);
      }
    }
    else {
      dVar9 = (double)FLOAT_803e8b6c;
      dVar8 = FUN_80293900((double)(float)((double)(float)(dVar9 * (double)((FLOAT_803df118 *
                                                                            FLOAT_803df118) /
                                                                           (float)(dVar9 * dVar8)))
                                          * dVar11));
      *(float *)(param_9 + 0x28) = (float)-dVar8;
      if (FLOAT_803e8c84 <= *(float *)(param_9 + 0x28)) {
        cVar1 = *(char *)(iVar7 + 0x8c8);
        if (((cVar1 != 'H') && (cVar1 != 'G')) && (cVar1 != 'B')) {
          param_12 = 0;
          param_13 = 0;
          param_14 = 0;
          param_15 = 0xff;
          param_16 = *DAT_803dd6d0;
          (**(code **)(param_16 + 0x1c))(0x42,0,1);
          *(undefined *)(iVar7 + 0x8c8) = 0x42;
        }
        *(undefined4 *)(iVar7 + 0x500) = *(undefined4 *)(param_9 + 0x10);
        uVar2 = *(undefined4 *)(iVar7 + 0x4ec);
        *(undefined4 *)(param_9 + 0x1c) = uVar2;
        *(undefined4 *)(param_9 + 0x10) = uVar2;
        fVar4 = FLOAT_803e8b3c;
        if (-1 < *(char *)(iVar7 + 0x547)) {
          param_10[0xa5] = (uint)FLOAT_803e8b3c;
          param_10[0xa1] = (uint)fVar4;
          param_10[0xa0] = (uint)fVar4;
          *(float *)(param_9 + 0x24) = fVar4;
          *(float *)(param_9 + 0x28) = fVar4;
          *(float *)(param_9 + 0x2c) = fVar4;
          FUN_802abd04(param_9,iVar7,5);
          *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0x7f;
          *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xef;
          *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xf7;
          FUN_8017082c();
          *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xfd;
          *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x800000;
          FUN_80035f9c(param_9);
          *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xbf;
          *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xfb | 4;
          *(byte *)(iVar7 + 0x3f4) = *(byte *)(iVar7 + 0x3f4) & 0xef | 0x10;
          *(undefined *)(iVar7 + 0x800) = 0;
          iVar5 = *(int *)(iVar7 + 0x7f8);
          if (iVar5 != 0) {
            if ((*(short *)(iVar5 + 0x46) == 0x3cf) || (*(short *)(iVar5 + 0x46) == 0x662)) {
              FUN_80182a5c(iVar5);
            }
            else {
              FUN_800ea9f8(iVar5);
            }
            *(ushort *)(*(int *)(iVar7 + 0x7f8) + 6) =
                 *(ushort *)(*(int *)(iVar7 + 0x7f8) + 6) & 0xbfff;
            *(undefined4 *)(*(int *)(iVar7 + 0x7f8) + 0xf8) = 0;
            *(undefined4 *)(iVar7 + 0x7f8) = 0;
          }
          param_10[0xc2] = (uint)FUN_802a58ac;
          return 3;
        }
        FUN_8003042c((double)FLOAT_803e8b3c,dVar9,dVar11,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x37,1,param_12,param_13,param_14,param_15,param_16);
        param_10[0xa8] = (uint)FLOAT_803e8c64;
        *(float *)(param_9 + 0x28) = FLOAT_803e8b3c;
      }
    }
  }
  else if (sVar3 < 0x36) {
    if (0x34 < sVar3) {
      if (*(char *)((int)param_10 + 0x346) != '\0') {
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x36,0,param_12,param_13,param_14,param_15,param_16);
        param_10[0xa8] = (uint)FLOAT_803e8bb8;
      }
      goto LAB_802a1f74;
    }
  }
  else if (sVar3 < 0x38) {
    if ((param_10[0xc5] & 1) != 0) {
      uVar6 = FUN_8006eea0((uint)*(byte *)(iVar7 + 0x86c),*(undefined *)(iVar7 + 0x8a5));
      FUN_8000bb38(param_9,uVar6);
      FUN_80014acc((double)FLOAT_803e8ba8);
      if (FLOAT_803e8b3c < *(float *)(iVar7 + 0x838)) {
        param_4 = (double)FLOAT_803e8cb0;
        (**(code **)(*DAT_803dd718 + 0x10))
                  ((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0x10),
                   (double)*(float *)(param_9 + 0x14),param_9);
      }
    }
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      *(undefined4 *)(param_9 + 0x18) = *(undefined4 *)(iVar7 + 0x768);
      *(undefined4 *)(param_9 + 0x20) = *(undefined4 *)(iVar7 + 0x770);
      if (*(int *)(param_9 + 0x30) != 0) {
        *(float *)(param_9 + 0x18) = *(float *)(param_9 + 0x18) + FLOAT_803dda58;
        *(float *)(param_9 + 0x20) = *(float *)(param_9 + 0x20) + FLOAT_803dda5c;
      }
      dVar8 = (double)FLOAT_803e8b3c;
      dVar11 = (double)*(float *)(param_9 + 0x20);
      iVar5 = *(int *)(param_9 + 0x30);
      FUN_8000e054((double)*(float *)(param_9 + 0x18),dVar8,dVar11,(float *)(param_9 + 0xc),
                   afStack_38,(float *)(param_9 + 0x14),iVar5);
      FUN_802abd04(param_9,iVar7,5);
      FUN_8003042c((double)FLOAT_803e8b3c,dVar8,dVar11,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)**(short **)(iVar7 + 0x3f8),1,iVar5,param_13,param_14,param_15,
                   param_16);
      *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x800000;
      param_10[0xc2] = (uint)FUN_802a58ac;
      return 2;
    }
  }
  dVar8 = (double)*(float *)(param_9 + 0xc);
  dVar11 = (double)*(float *)(param_9 + 0x14);
  sVar3 = *(short *)(param_9 + 0xa0);
  if (sVar3 != 0x36) {
    if (sVar3 < 0x36) {
      if (0x34 < sVar3) {
        dVar9 = (double)(*(float *)(param_9 + 0x98) *
                         (*(float *)(param_9 + 0x10) - *(float *)(iVar7 + 0x500)) +
                        *(float *)(iVar7 + 0x500));
        goto LAB_802a23b4;
      }
    }
    else if (sVar3 < 0x38) {
      dVar10 = (double)*(float *)(param_9 + 0x98);
      dVar8 = (double)(float)(dVar10 * (double)(float)((double)*(float *)(iVar7 + 0x768) - dVar8) +
                             dVar8);
      dVar9 = (double)((float)((double)FLOAT_803e8b78 - dVar10) *
                       (*(float *)(iVar7 + 0x500) - *(float *)(param_9 + 0x10)) +
                      *(float *)(param_9 + 0x10));
      dVar11 = (double)(float)(dVar10 * (double)(float)((double)*(float *)(iVar7 + 0x770) - dVar11)
                              + dVar11);
      goto LAB_802a23b4;
    }
  }
  dVar9 = (double)*(float *)(param_9 + 0x10);
LAB_802a23b4:
  (**(code **)(*DAT_803dd6d0 + 0x2c))(dVar8,dVar9,dVar11);
  FUN_802abd04(param_9,iVar7,5);
  return 0;
}

