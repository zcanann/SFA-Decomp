// Function: FUN_801f2290
// Entry: 801f2290
// Size: 1364 bytes

/* WARNING: Removing unreachable block (ram,0x801f27b8) */
/* WARNING: Removing unreachable block (ram,0x801f27b0) */
/* WARNING: Removing unreachable block (ram,0x801f27c0) */

void FUN_801f2290(short *param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  short sVar4;
  float *pfVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined auStack108 [28];
  double local_50;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  pfVar5 = *(float **)(param_1 + 0x5c);
  FUN_8002b9ec();
  local_78 = DAT_802c2470;
  local_74 = DAT_802c2474;
  local_70 = DAT_802c2478;
  *(float *)(param_1 + 8) = pfVar5[1];
  iVar3 = FUN_8001ffb4(0x1fc);
  if (iVar3 == 0) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    if (*(short *)(pfVar5 + 8) < 1) {
      iVar3 = FUN_800221a0(1,4);
      if (iVar3 == 3) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 3;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if (iVar3 < 3) {
        if (iVar3 == 1) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 1;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
        else if (0 < iVar3) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 2;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
      }
      else if (iVar3 == 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 5;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if (iVar3 < 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 4;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
    }
    else {
      uVar2 = (uint)*(byte *)((int)pfVar5 + 0x22);
      if (uVar2 == 0xc) {
        iVar3 = (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14;
        sVar4 = FUN_800217c0((double)*(float *)(&DAT_80328974 + iVar3),
                             (double)*(float *)(&DAT_80328978 + iVar3));
        iVar3 = (int)(short)(sVar4 - *param_1);
        FUN_80137948(s_diff__d_80328a24,iVar3);
        if ((iVar3 < -1000) || (1000 < iVar3)) {
          if (iVar3 < 1) {
            *param_1 = *param_1 + (ushort)DAT_803db410 * -100;
          }
          else {
            *param_1 = *param_1 + (ushort)DAT_803db410 * 100;
          }
        }
        else {
          local_50 = (double)(longlong)
                             (int)*(float *)(&DAT_8032897c +
                                            (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          FUN_80030334((double)FLOAT_803e5d98,param_1,
                       (int)*(float *)(&DAT_8032897c + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14),0
                      );
          pfVar5[3] = *(float *)(&DAT_80328984 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          *(undefined *)((int)pfVar5 + 0x22) = 0xd;
        }
      }
      else if (uVar2 == 0xd) {
        iVar3 = FUN_8002fa48((double)pfVar5[3],(double)FLOAT_803db414,param_1,auStack108);
        if (iVar3 != 0) {
          local_50 = (double)CONCAT44(0x43300000,(int)param_1[0x50] ^ 0x80000000);
          iVar3 = (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14;
          if ((float)(local_50 - DOUBLE_803e5db8) == *(float *)(&DAT_8032897c + iVar3)) {
            local_50 = (double)(longlong)(int)*(float *)(&DAT_80328980 + iVar3);
            FUN_80030334((double)FLOAT_803e5d98,param_1,(int)*(float *)(&DAT_80328980 + iVar3),0);
            pfVar5[3] = *(float *)(&DAT_80328984 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          }
        }
        *(ushort *)(pfVar5 + 8) = *(short *)(pfVar5 + 8) - (ushort)DAT_803db410;
        if (*(short *)(pfVar5 + 8) < 1) {
          *(undefined2 *)(pfVar5 + 8) = 0;
        }
      }
      else {
        dVar9 = (double)(*(float *)(&DAT_80328974 + uVar2 * 0x14) -
                        (*(float *)(param_1 + 6) - *pfVar5));
        dVar8 = (double)(*(float *)(&DAT_80328978 + uVar2 * 0x14) -
                        (*(float *)(param_1 + 10) - pfVar5[2]));
        dVar7 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8))
                                    );
        sVar4 = FUN_800217c0(dVar9,dVar8);
        sVar4 = sVar4 - *param_1;
        if ((sVar4 < -1000) || (1000 < sVar4)) {
          if (param_1[0x50] != 0xc) {
            FUN_80030334((double)FLOAT_803e5d98,param_1,0xc,0);
            pfVar5[3] = FLOAT_803e5db0;
          }
          if (sVar4 < 1) {
            *param_1 = *param_1 + (ushort)DAT_803db410 * -300;
          }
          else {
            *param_1 = *param_1 + (ushort)DAT_803db410 * 300;
          }
        }
        else {
          if (param_1[0x50] != 0x3b) {
            FUN_80030334((double)FLOAT_803e5d98,param_1,0x3b,0);
            pfVar5[3] = FLOAT_803e5da8;
          }
          fVar1 = FLOAT_803e5dac;
          *(float *)(param_1 + 0x12) = FLOAT_803e5dac * (float)(dVar9 / dVar7);
          *(float *)(param_1 + 0x16) = fVar1 * (float)(dVar8 / dVar7);
          FUN_8002f5d4(param_1,pfVar5 + 3);
        }
        if (dVar7 < (double)FLOAT_803e5db4) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 0xc;
          fVar1 = FLOAT_803e5d98;
          *(float *)(param_1 + 0x12) = FLOAT_803e5d98;
          *(float *)(param_1 + 0x16) = fVar1;
        }
        *(float *)(param_1 + 6) =
             *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
        *(float *)(param_1 + 10) =
             *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
        FUN_8002fa48((double)pfVar5[3],(double)FLOAT_803db414,param_1,auStack108);
      }
    }
  }
  else {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
    if (((*(byte *)((int)param_1 + 0xaf) & 1) != 0) &&
       (iVar3 = (**(code **)(*DAT_803dca68 + 0x24))(&local_78,3), -1 < iVar3)) {
      FUN_800200e8(0x4d1,1);
      *(char *)((int)pfVar5 + 0x27) = *(char *)((int)pfVar5 + 0x27) + '\x01';
      FUN_800200e8(0x310,1);
      FUN_80014b3c(0,0x100);
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  return;
}

