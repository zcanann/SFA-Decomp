// Function: FUN_8021c840
// Entry: 8021c840
// Size: 1532 bytes

/* WARNING: Removing unreachable block (ram,0x8021ce0c) */
/* WARNING: Removing unreachable block (ram,0x8021ce14) */

void FUN_8021c840(short *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  short sVar6;
  short sVar7;
  int iVar8;
  float *pfVar9;
  undefined4 uVar10;
  undefined8 uVar11;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  undefined4 local_58;
  undefined4 local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack68 [12];
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  pfVar9 = *(float **)(param_1 + 0x5c);
  iVar8 = *(int *)(param_1 + 0x26);
  FUN_8002b9ec();
  iVar4 = FUN_8021bf9c(param_1);
  if (iVar4 == 0) {
    if ((*(byte *)(pfVar9 + 0x5e) >> 5 & 1) == 0) {
      uVar5 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x20));
      *(byte *)(pfVar9 + 0x5e) =
           (byte)((uVar5 & 0xff) << 5) & 0x20 | *(byte *)(pfVar9 + 0x5e) & 0xdf;
      pfVar9[0x45] = FLOAT_803e6a3c;
      if ((*(byte *)(pfVar9 + 0x5e) >> 5 & 1) != 0) {
        local_58 = 0x2a;
        (**(code **)(*DAT_803dca9c + 0x8c))
                  ((double)FLOAT_803e6a4c,pfVar9 + 1,param_1,&local_58,0xffffffff);
        FUN_80010320((double)FLOAT_803e6a50,pfVar9 + 1);
        *(float *)(param_1 + 6) = pfVar9[0x1b];
        *(float *)(param_1 + 8) = pfVar9[0x1c];
        *(float *)(param_1 + 10) = pfVar9[0x1d];
        *pfVar9 = FLOAT_803e6a38;
        FUN_8000bb18(param_1,0x308);
        FUN_8000bb18(param_1,0x30a);
      }
    }
    else {
      if ((*(byte *)((int)pfVar9 + 0x179) >> 3 & 1) == 0) {
        FUN_80035f00(param_1);
        pfVar9[0x44] = *pfVar9;
        FLOAT_803dc2f8 = FLOAT_803e6a38 * *pfVar9;
      }
      else {
        uVar11 = FUN_802931a0((double)(pfVar9[0x1e] * pfVar9[0x1e] + pfVar9[0x20] * pfVar9[0x20]));
        sVar6 = FUN_800217c0(uVar11,(double)pfVar9[0x1f]);
        uStack52 = (int)sVar6 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar14 = (double)((FLOAT_803e6a54 *
                          (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e6a60)) /
                         FLOAT_803e6a58);
        dVar12 = (double)FUN_80294204(dVar14);
        dVar13 = (double)(float)((double)FLOAT_803e6a8c * dVar12);
        dVar12 = (double)FUN_80293e80(dVar14);
        fVar3 = FLOAT_803e6a90 * (float)((double)FLOAT_803e6a94 * dVar12);
        if ((*(byte *)(pfVar9 + 0x5e) >> 6 & 1) != 0) {
          fVar1 = *pfVar9;
          if (fVar1 < FLOAT_803e6a3c) {
            fVar1 = -fVar1;
          }
          fVar2 = pfVar9[0x44];
          if (fVar2 < FLOAT_803e6a3c) {
            fVar2 = -fVar2;
          }
          if (FLOAT_803e6a38 + fVar1 < fVar2) {
            fVar3 = fVar3 + FLOAT_803e6a38;
          }
        }
        if ((*(byte *)(pfVar9 + 0x5e) >> 1 & 0xf) != 0) {
          fVar3 = fVar3 + FLOAT_803e6a38;
        }
        pfVar9[0x44] = pfVar9[0x45] + (float)((double)pfVar9[0x44] + dVar13);
        fVar1 = pfVar9[0x44];
        fVar2 = fVar1;
        if (fVar1 < FLOAT_803e6a3c) {
          fVar2 = -fVar1;
        }
        if (fVar3 <= fVar2) {
          if (*pfVar9 < fVar1) {
            fVar3 = -fVar3;
          }
          pfVar9[0x44] = pfVar9[0x44] + fVar3;
        }
        else {
          pfVar9[0x44] = *pfVar9;
        }
        FUN_80035df4(param_1,8,1,0);
      }
      if (FLOAT_803e6a3c <= pfVar9[0x44]) {
        (**(code **)(*DAT_803dca9c + 0x94))(pfVar9 + 1,0);
      }
      else {
        (**(code **)(*DAT_803dca9c + 0x94))(pfVar9 + 1,1);
      }
      fVar3 = FLOAT_803e6a3c;
      pfVar9[0x45] = FLOAT_803e6a3c;
      if (fVar3 != pfVar9[0x44]) {
        FUN_80010320(pfVar9 + 1);
        if ((((pfVar9[0x21] == 0.0) && (pfVar9[5] != 0.0)) ||
            ((pfVar9[0x21] != 0.0 && (pfVar9[5] == 0.0)))) &&
           (iVar4 = FUN_8021c0d0(param_1,*(undefined *)((int)pfVar9[0x29] + 0x18),
                                 *(undefined *)((int)pfVar9[0x2a] + 0x18),&local_54), iVar4 != 0)) {
          FUN_8021b898(pfVar9 + 1,local_54);
        }
      }
      local_50 = pfVar9[0x1b];
      local_4c = pfVar9[0x1c];
      local_48 = pfVar9[0x1d];
      uStack52 = (int)*(short *)(pfVar9 + 0x5d) ^ 0x80000000;
      local_38 = 0x43300000;
      dVar12 = (double)FUN_80293e80((double)((FLOAT_803e6a54 *
                                             (float)((double)CONCAT44(0x43300000,uStack52) -
                                                    DOUBLE_803e6a60)) / FLOAT_803e6a58));
      local_4c = local_4c + (float)((double)FLOAT_803e6a48 + dVar12);
      *(ushort *)(pfVar9 + 0x5d) = *(short *)(pfVar9 + 0x5d) + (ushort)DAT_803db410 * 800;
      if ((*(byte *)((int)pfVar9 + 0x179) >> 4 & 1) == 0) {
        uVar11 = FUN_802931a0((double)(pfVar9[0x1e] * pfVar9[0x1e] + pfVar9[0x20] * pfVar9[0x20]));
        sVar6 = FUN_800217c0((double)pfVar9[0x1e],(double)pfVar9[0x20]);
        sVar6 = (sVar6 + -0x8000) - *param_1;
        sVar7 = FUN_800217c0((double)pfVar9[0x1f],uVar11);
        param_1[1] = sVar7;
        if (sVar6 < -0x800) {
          sVar6 = -0x800;
        }
        else if (0x800 < sVar6) {
          sVar6 = 0x800;
        }
        sVar7 = sVar6;
        if (FLOAT_803e6a3c <= pfVar9[0x44]) {
          sVar7 = -sVar6;
        }
        param_1[2] = sVar7;
        if (sVar6 < -0x100) {
          sVar6 = -0x100;
        }
        else if (0x100 < sVar6) {
          sVar6 = 0x100;
        }
        *param_1 = *param_1 + sVar6;
        sVar6 = param_1[1];
        if (sVar6 < -100) {
          sVar6 = -100;
        }
        else if (100 < sVar6) {
          sVar6 = 100;
        }
        param_1[1] = sVar6;
      }
      else {
        iVar4 = FUN_80036e58(0x45,param_1,0);
        if (iVar4 != 0) {
          sVar6 = FUN_800385e8(param_1,iVar4,0);
          if (sVar6 < -0x200) {
            sVar6 = -0x200;
          }
          else if (0x200 < sVar6) {
            sVar6 = 0x200;
          }
          *param_1 = *param_1 + sVar6;
          sVar7 = param_1[1];
          if (sVar7 != 0) {
            if (sVar7 < -0x100) {
              sVar7 = -0x100;
            }
            else if (0x100 < sVar7) {
              sVar7 = 0x100;
            }
            param_1[1] = param_1[1] - sVar7;
          }
          param_1[2] = sVar6 * DAT_803dc2fc;
        }
      }
      FUN_80247754(&local_50,param_1 + 6,auStack68);
      FUN_80221f14((double)FLOAT_803dc2f8,
                   (double)(float)((double)FLOAT_803dc2f8 / (double)FLOAT_803e6a98),
                   (double)FLOAT_803e6a9c,param_1,param_1 + 0x12,auStack68);
      FUN_80247730(param_1 + 6,param_1 + 0x12,param_1 + 6);
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  return;
}

