// Function: FUN_801a6054
// Entry: 801a6054
// Size: 1224 bytes

/* WARNING: Removing unreachable block (ram,0x801a60b0) */
/* WARNING: Removing unreachable block (ram,0x801a64f4) */

void FUN_801a6054(undefined2 *param_1)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  undefined2 uVar7;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar8;
  short *psVar9;
  int iVar10;
  undefined4 uVar11;
  undefined8 in_f31;
  double dVar12;
  undefined auStack72 [4];
  undefined auStack68 [4];
  int local_40 [2];
  double local_38;
  double local_30;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar10 = *(int *)(param_1 + 0x5c);
  local_40[0] = 0;
  psVar9 = *(short **)(param_1 + 0x26);
  iVar8 = 0;
  bVar1 = *(byte *)(iVar10 + 0x114);
  if (bVar1 == 2) {
    *(float *)(iVar10 + 0x110) = *(float *)(iVar10 + 0x110) + FLOAT_803db414;
    fVar2 = FLOAT_803e44b0;
    if (FLOAT_803e44b0 <= *(float *)(iVar10 + 0x110)) {
      *(undefined *)(iVar10 + 0x116) = 0;
      *(undefined *)(iVar10 + 0x114) = 3;
      *(float *)(iVar10 + 0x110) = *(float *)(iVar10 + 0x110) - fVar2;
      FUN_80037200(param_1,0x2f);
      DAT_803ddb20 = DAT_803ddb20 + -1;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      if (*psVar9 == 0x72a) {
        dVar12 = (double)FLOAT_803e446c;
        for (fVar2 = FLOAT_803e4468;
            (iVar8 == 0 && (fVar2 < (float)(dVar12 * (double)FLOAT_803db414)));
            fVar2 = fVar2 * fVar2 + fVar3 * fVar3) {
          iVar8 = FUN_80010320((double)*(float *)(iVar10 + 0x108),iVar10);
          if ((iVar8 == 0) && (*(int *)(iVar10 + 0x10) != 0)) {
            (**(code **)(*DAT_803dca9c + 0x90))(iVar10);
          }
          fVar2 = *(float *)(iVar10 + 0x68) - *(float *)(param_1 + 0x40);
          fVar3 = *(float *)(iVar10 + 0x70) - *(float *)(param_1 + 0x44);
        }
      }
      else {
        iVar8 = FUN_80010320((double)*(float *)(iVar10 + 0x108),iVar10);
        if ((iVar8 == 0) && (*(int *)(iVar10 + 0x10) != 0)) {
          (**(code **)(*DAT_803dca9c + 0x90))(iVar10);
        }
      }
      *(undefined *)(iVar10 + 0x116) = 10;
      FUN_80035974(param_1,*(undefined *)(*(int *)(param_1 + 0x28) + 0x62));
      if (*psVar9 == 0x72a) {
        fVar2 = FLOAT_803e4478 + *(float *)(iVar10 + 0x6c);
      }
      else {
        fVar2 = *(float *)(iVar10 + 0x6c);
      }
      dVar12 = (double)fVar2;
      *(float *)(iVar10 + 0x10c) = FLOAT_803e4498 * FLOAT_803db414 + *(float *)(iVar10 + 0x10c);
      *(float *)(param_1 + 8) =
           *(float *)(iVar10 + 0x10c) * FLOAT_803db414 + *(float *)(param_1 + 8);
      if ((double)*(float *)(param_1 + 8) < dVar12) {
        if ((*psVar9 == 0x72a) && ((double)*(float *)(param_1 + 8) < (double)FLOAT_803e449c)) {
          iVar8 = 1;
        }
        if ((iVar8 == 0) &&
           (FLOAT_803e446c < *(float *)(iVar10 + 0x10c) * *(float *)(iVar10 + 0x10c))) {
          FUN_8000b4d0(param_1,0x41e,6);
        }
        *(float *)(iVar10 + 0x10c) = *(float *)(iVar10 + 0x10c) * FLOAT_803e44a0;
        *(float *)(param_1 + 8) =
             (float)((double)FLOAT_803e44a4 * dVar12 - (double)*(float *)(param_1 + 8));
      }
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar10 + 0x68);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar10 + 0x70);
      uVar7 = FUN_800217c0((double)*(float *)(iVar10 + 0x74),(double)*(float *)(iVar10 + 0x7c));
      *param_1 = uVar7;
      if (*(char *)(iVar10 + 0x115) == '\0') {
        local_30 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
        param_1[2] = (short)(int)-(FLOAT_803e44a8 * FLOAT_803db414 -
                                  (float)(local_30 - DOUBLE_803e4488));
        if ((short)param_1[2] < 0x3a00) {
          *(undefined *)(iVar10 + 0x115) = 1;
        }
      }
      else {
        local_38 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
        param_1[2] = (short)(int)(FLOAT_803e44a8 * FLOAT_803db414 +
                                 (float)(local_38 - DOUBLE_803e4488));
        if (0x5000 < (short)param_1[2]) {
          *(undefined *)(iVar10 + 0x115) = 0;
        }
      }
      local_30 = (double)CONCAT44(0x43300000,(int)(short)param_1[1] ^ 0x80000000);
      iVar4 = (int)(FLOAT_803e44ac * FLOAT_803db414 * *(float *)(iVar10 + 0x108) +
                   (float)(local_30 - DOUBLE_803e4488));
      local_38 = (double)(longlong)iVar4;
      param_1[1] = (short)iVar4;
      iVar4 = FUN_8003687c(param_1,local_40,auStack68,auStack72);
      if ((((iVar8 != 0) || (iVar5 = FUN_8002b9ec(), local_40[0] == iVar5)) || (iVar4 - 0xeU < 2))
         || (iVar4 == 0x13)) {
        if (iVar8 == 0) {
          *(undefined *)(iVar10 + 0x116) = 0;
        }
        else {
          *(undefined *)(iVar10 + 0x116) = 5;
        }
        uVar6 = FUN_800221a0(0,2);
        FUN_801a5d88(param_1,uVar6);
      }
    }
    else {
      *(float *)(iVar10 + 0x110) = *(float *)(iVar10 + 0x110) + FLOAT_803db414;
      fVar2 = FLOAT_803e44b0;
      if (FLOAT_803e44b0 <= *(float *)(iVar10 + 0x110)) {
        *(undefined *)(iVar10 + 0x114) = 2;
        *(float *)(iVar10 + 0x110) = *(float *)(iVar10 + 0x110) - fVar2;
      }
    }
  }
  else if ((bVar1 < 4) &&
          (*(float *)(iVar10 + 0x110) = *(float *)(iVar10 + 0x110) + FLOAT_803db414,
          FLOAT_803e44b4 <= *(float *)(iVar10 + 0x110))) {
    FUN_8002cbc4();
    goto LAB_801a64f4;
  }
  if (*(char *)(iVar10 + 0x116) == '\0') {
    FUN_80035f00(param_1);
    FUN_80035df4(param_1,*(undefined *)(iVar10 + 0x116),0,0);
  }
  else {
    FUN_80035f20(param_1);
    FUN_80035df4(param_1,*(undefined *)(iVar10 + 0x116),1,0);
  }
LAB_801a64f4:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return;
}

