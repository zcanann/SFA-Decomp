// Function: FUN_801f28c8
// Entry: 801f28c8
// Size: 1364 bytes

/* WARNING: Removing unreachable block (ram,0x801f2df8) */
/* WARNING: Removing unreachable block (ram,0x801f2df0) */
/* WARNING: Removing unreachable block (ram,0x801f2de8) */
/* WARNING: Removing unreachable block (ram,0x801f28e8) */
/* WARNING: Removing unreachable block (ram,0x801f28e0) */
/* WARNING: Removing unreachable block (ram,0x801f28d8) */

void FUN_801f28c8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined8 local_50;
  
  pfVar5 = *(float **)(param_9 + 0x5c);
  FUN_8002bac4();
  local_78 = DAT_802c2bf0;
  local_74 = DAT_802c2bf4;
  local_70 = DAT_802c2bf8;
  *(float *)(param_9 + 8) = pfVar5[1];
  uVar3 = FUN_80020078(0x1fc);
  if (uVar3 == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    if (*(short *)(pfVar5 + 8) < 1) {
      uVar3 = FUN_80022264(1,4);
      if (uVar3 == 3) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 3;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 3) {
        if (uVar3 == 1) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 1;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
        else if (0 < (int)uVar3) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 2;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
      }
      else if (uVar3 == 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 5;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 4;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
    }
    else {
      uVar3 = (uint)*(byte *)((int)pfVar5 + 0x22);
      if (uVar3 == 0xc) {
        dVar7 = (double)*(float *)(&DAT_803295b8 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
        iVar4 = FUN_80021884();
        sVar2 = (short)iVar4 - *param_9;
        FUN_80137cd0();
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -100;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 100;
          }
        }
        else {
          local_50 = (double)(longlong)
                             (int)*(float *)(&DAT_803295bc +
                                            (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          FUN_8003042c((double)FLOAT_803e6a30,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,(int)*(float *)(&DAT_803295bc +
                                              (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14),0,param_12
                       ,param_13,param_14,param_15,param_16);
          pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          *(undefined *)((int)pfVar5 + 0x22) = 0xd;
        }
      }
      else if (uVar3 == 0xd) {
        dVar7 = (double)FLOAT_803dc074;
        iVar4 = FUN_8002fb40((double)pfVar5[3],dVar7);
        if (iVar4 != 0) {
          local_50 = (double)CONCAT44(0x43300000,(int)param_9[0x50] ^ 0x80000000);
          iVar4 = (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14;
          if ((float)(local_50 - DOUBLE_803e6a50) == *(float *)(&DAT_803295bc + iVar4)) {
            local_50 = (double)(longlong)(int)*(float *)(&DAT_803295c0 + iVar4);
            FUN_8003042c((double)FLOAT_803e6a30,dVar7,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,(int)*(float *)(&DAT_803295c0 + iVar4),0,param_12,param_13,
                         param_14,param_15,param_16);
            pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          }
        }
        *(ushort *)(pfVar5 + 8) = *(short *)(pfVar5 + 8) - (ushort)DAT_803dc070;
        if (*(short *)(pfVar5 + 8) < 1) {
          *(undefined2 *)(pfVar5 + 8) = 0;
        }
      }
      else {
        dVar9 = (double)(*(float *)(&DAT_803295b4 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 6) - *pfVar5));
        dVar8 = (double)(*(float *)(&DAT_803295b8 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 10) - pfVar5[2]));
        dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)));
        dVar7 = dVar8;
        iVar4 = FUN_80021884();
        sVar2 = (short)iVar4 - *param_9;
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (param_9[0x50] != 0xc) {
            FUN_8003042c((double)FLOAT_803e6a30,dVar8,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0xc,0,param_12,param_13,param_14,param_15,param_16);
            pfVar5[3] = FLOAT_803e6a48;
          }
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -300;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 300;
          }
        }
        else {
          if (param_9[0x50] != 0x3b) {
            FUN_8003042c((double)FLOAT_803e6a30,dVar8,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0x3b,0,param_12,param_13,param_14,param_15,param_16);
            pfVar5[3] = FLOAT_803e6a40;
          }
          dVar8 = (double)FLOAT_803e6a44;
          *(float *)(param_9 + 0x12) = (float)(dVar8 * (double)(float)(dVar9 / dVar6));
          *(float *)(param_9 + 0x16) = (float)(dVar8 * (double)(float)(dVar7 / dVar6));
          FUN_8002f6cc(dVar8,(int)param_9,pfVar5 + 3);
        }
        if (dVar6 < (double)FLOAT_803e6a4c) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 0xc;
          fVar1 = FLOAT_803e6a30;
          *(float *)(param_9 + 0x12) = FLOAT_803e6a30;
          *(float *)(param_9 + 0x16) = fVar1;
        }
        *(float *)(param_9 + 6) =
             *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(param_9 + 6);
        *(float *)(param_9 + 10) =
             *(float *)(param_9 + 0x16) * FLOAT_803dc074 + *(float *)(param_9 + 10);
        FUN_8002fb40((double)pfVar5[3],(double)FLOAT_803dc074);
      }
    }
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    if (((*(byte *)((int)param_9 + 0xaf) & 1) != 0) &&
       (iVar4 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_78,3), -1 < iVar4)) {
      FUN_800201ac(0x4d1,1);
      *(char *)((int)pfVar5 + 0x27) = *(char *)((int)pfVar5 + 0x27) + '\x01';
      FUN_800201ac(0x310,1);
      FUN_80014b68(0,0x100);
    }
  }
  return;
}

