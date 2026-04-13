// Function: FUN_801d3244
// Entry: 801d3244
// Size: 1508 bytes

/* WARNING: Removing unreachable block (ram,0x801d32a8) */

void FUN_801d3244(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,uint *param_12,
                 float *param_13,undefined4 *param_14,float *param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  double dVar8;
  undefined4 uStack_48;
  uint local_44;
  int iStack_40;
  undefined auStack_3c [12];
  float local_30;
  undefined4 uStack_2c;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  FUN_8002bac4();
  bVar3 = FUN_8002b11c((int)param_9);
  if (bVar3 != 0) {
    return;
  }
  pfVar7 = *(float **)(param_9 + 0x5c);
  uVar5 = (uint)*(byte *)(pfVar7 + 5);
  iVar4 = uVar5 * 0xc;
  if (uVar5 == 2) {
    if ((*(byte *)((int)pfVar7 + 0x15) & 2) != 0) {
      FUN_8000bb38((uint)param_9,0xa1);
      *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) & 0xfd;
      iVar6 = *(int *)(param_9 + 0x26);
      *(undefined *)(param_9 + 0x1b) = 0xff;
      param_9[3] = param_9[3] & 0xbfff;
      *(undefined4 *)(param_9 + 6) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)(param_9 + 8) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)(param_9 + 10) = *(undefined4 *)(iVar6 + 0x10);
      *(float *)(param_9 + 4) = FLOAT_803e5ff0;
      pfVar7[2] = FLOAT_803e5ff4;
      pfVar7[1] = pfVar7[3];
      pfVar7[4] = pfVar7[1] / pfVar7[2];
      *pfVar7 = pfVar7[2];
      FUN_8003613c((int)param_9);
    }
    if (pfVar7[1] < *(float *)(param_9 + 4)) {
      pfVar7[4] = pfVar7[4] / FLOAT_803e6014;
    }
    if (pfVar7[4] < FLOAT_803e5ff0) {
      pfVar7[4] = FLOAT_803e6004;
    }
    param_2 = (double)pfVar7[4];
    *(float *)(param_9 + 4) =
         (float)(param_2 * (double)FLOAT_803dc074 + (double)*(float *)(param_9 + 4));
    fVar1 = *pfVar7 - FLOAT_803dc074;
    *pfVar7 = fVar1;
    if (fVar1 < FLOAT_803e6004) {
      *(undefined *)(pfVar7 + 5) = 0;
      *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) | 2;
    }
  }
  else {
    if (uVar5 < 2) {
      if (uVar5 != 0) {
        iVar6 = *(int *)(param_9 + 0x26);
        if ((*(byte *)((int)pfVar7 + 0x15) & 2) != 0) {
          *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) & 0xfd;
          uStack_1c = (int)*(short *)(iVar6 + 0x18) ^ 0x80000000;
          local_20 = 0x43300000;
          *pfVar7 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5ff8);
        }
        uVar5 = (uint)*(short *)(iVar6 + 0x1c);
        if (uVar5 == 0xffffffff) {
          fVar1 = *pfVar7 - FLOAT_803dc074;
          *pfVar7 = fVar1;
          if (fVar1 <= FLOAT_803e6004) {
            iVar6 = FUN_8002bac4();
            dVar8 = FUN_80021794((float *)(param_9 + 0xc),(float *)(iVar6 + 0x18));
            if ((double)FLOAT_803e6000 < dVar8) {
              *(undefined *)(pfVar7 + 5) = 2;
              *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) | 2;
            }
            *pfVar7 = FLOAT_803e6004;
          }
        }
        else {
          uVar5 = FUN_80020078(uVar5);
          if (uVar5 != 0) {
            iVar6 = FUN_8002bac4();
            dVar8 = FUN_80021794((float *)(param_9 + 0xc),(float *)(iVar6 + 0x18));
            if ((double)FLOAT_803e6000 < dVar8) {
              *(undefined *)(pfVar7 + 5) = 2;
              *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) | 2;
            }
          }
        }
        goto LAB_801d3580;
      }
      FUN_8000da78((uint)param_9,0x3fd);
    }
    else if (uVar5 == 4) {
      FUN_801d3160(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   &DAT_80327960 + iVar4,(int)pfVar7);
      goto LAB_801d3580;
    }
    iVar6 = *(int *)(param_9 + 0x26);
    if ((*(byte *)((int)pfVar7 + 0x15) & 2) != 0) {
      *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) & 0xfd;
      uVar5 = FUN_80022264(0xffffffce,0x32);
      uStack_1c = (int)*(short *)(iVar6 + 0x1a) + uVar5 ^ 0x80000000;
      local_20 = 0x43300000;
      *pfVar7 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5ff8);
    }
    if ((param_9[0x58] & 0x800) != 0) {
      param_12 = (uint *)0x2;
      param_13 = (float *)0xffffffff;
      param_14 = (undefined4 *)0x0;
      param_15 = (float *)*DAT_803dd708;
      (*(code *)param_15[2])(param_9,0x7f1,0);
    }
  }
LAB_801d3580:
  if (((&DAT_80327968)[iVar4] & 1) != 0) {
    param_12 = &local_44;
    param_13 = &local_30;
    param_14 = &uStack_2c;
    param_15 = local_28;
    iVar6 = FUN_80036868((int)param_9,&uStack_48,&iStack_40,param_12,param_13,param_14,param_15);
    if ((iVar6 != 0) && (local_44 != 0)) {
      if (iVar6 == 0x10) {
        FUN_8002b128(param_9,300);
      }
      else if ((iVar6 - 0xeU < 2) || (iVar6 == 0x11)) {
        FUN_8000bb38((uint)param_9,0x9d);
        local_30 = local_30 + FLOAT_803dda58;
        local_28[0] = local_28[0] + FLOAT_803dda5c;
        FUN_8009a468(param_9,auStack_3c,1,(int *)0x0);
        param_13 = (float *)0x0;
        param_14 = (undefined4 *)0x1;
        FUN_8002ad08(param_9,0xf,200,0,0,1);
        *(undefined *)(pfVar7 + 5) = 4;
        *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) | 2;
        iVar6 = *(int *)(param_9 + 0x28);
        sVar2 = *(short *)(iVar6 + 0x6a) + 0x50;
        param_12 = (uint *)(int)sVar2;
        FUN_80035c48((int)param_9,*(byte *)(iVar6 + 0x62) + 0x50,*(short *)(iVar6 + 0x68) + -0x50,
                     sVar2);
        FUN_80035f84((int)param_9);
      }
    }
  }
  if (((&DAT_80327968)[iVar4] & 8) == 0) {
    FUN_80035ff8((int)param_9);
  }
  else {
    FUN_80036018((int)param_9);
  }
  if (((&DAT_80327968)[iVar4] & 0x10) == 0) {
    FUN_80035ea4((int)param_9);
  }
  else {
    param_12 = (uint *)0x0;
    FUN_80035eec((int)param_9,5,1,0);
  }
  if (((&DAT_80327968)[iVar4] & 2) == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    if (((*(byte *)((int)param_9 + 0xaf) & 4) != 0) && (uVar5 = FUN_80020078(0x189), uVar5 == 0)) {
      param_12 = (uint *)*DAT_803dd6d4;
      (*(code *)param_12[0x12])(0,param_9,0xffffffff);
      FUN_800201ac(0x189,1);
    }
  }
  if (((&DAT_80327968)[iVar4] & 4) == 0) {
    param_9[3] = param_9[3] & 0xbfff;
  }
  else {
    param_9[3] = param_9[3] | 0x4000;
  }
  iVar6 = (int)*(short *)(&DAT_80327960 + iVar4);
  if ((short)param_9[0x50] != iVar6) {
    FUN_8003042c((double)FLOAT_803e6004,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,iVar6,0,param_12,param_13,param_14,param_15,param_16);
  }
  iVar4 = FUN_8002fb40((double)*(float *)(&DAT_80327964 + iVar4),(double)FLOAT_803dc074);
  if (iVar4 == 0) {
    *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) & 0xfe;
  }
  else {
    *(byte *)((int)pfVar7 + 0x15) = *(byte *)((int)pfVar7 + 0x15) | 1;
  }
  return;
}

