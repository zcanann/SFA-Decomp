// Function: FUN_801a6608
// Entry: 801a6608
// Size: 1224 bytes

/* WARNING: Removing unreachable block (ram,0x801a6aa8) */
/* WARNING: Removing unreachable block (ram,0x801a6664) */
/* WARNING: Removing unreachable block (ram,0x801a6618) */

void FUN_801a6608(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  float *pfVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  uint uStack_48;
  int iStack_44;
  int local_40 [2];
  undefined8 local_38;
  undefined8 local_30;
  
  pfVar7 = *(float **)(param_9 + 0x5c);
  local_40[0] = 0;
  psVar6 = *(short **)(param_9 + 0x26);
  iVar5 = 0;
  bVar1 = *(byte *)(pfVar7 + 0x45);
  if (bVar1 == 2) {
    pfVar7[0x44] = pfVar7[0x44] + FLOAT_803dc074;
    fVar2 = FLOAT_803e5148;
    if (FLOAT_803e5148 <= pfVar7[0x44]) {
      *(undefined *)((int)pfVar7 + 0x116) = 0;
      *(undefined *)(pfVar7 + 0x45) = 3;
      pfVar7[0x44] = pfVar7[0x44] - fVar2;
      FUN_800372f8((int)param_9,0x2f);
      DAT_803de7a0 = DAT_803de7a0 + -1;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      if (*psVar6 == 0x72a) {
        dVar10 = (double)FLOAT_803e5104;
        fVar2 = FLOAT_803e5100;
        while ((iVar5 == 0 && (fVar2 < (float)(dVar10 * (double)FLOAT_803dc074)))) {
          iVar5 = FUN_80010340((double)pfVar7[0x42],pfVar7);
          if ((iVar5 == 0) && (pfVar7[4] != 0.0)) {
            (**(code **)(*DAT_803dd71c + 0x90))(pfVar7);
          }
          fVar2 = (pfVar7[0x1a] - *(float *)(param_9 + 0x40)) *
                  (pfVar7[0x1a] - *(float *)(param_9 + 0x40)) +
                  (pfVar7[0x1c] - *(float *)(param_9 + 0x44)) *
                  (pfVar7[0x1c] - *(float *)(param_9 + 0x44));
        }
      }
      else {
        iVar5 = FUN_80010340((double)pfVar7[0x42],pfVar7);
        if ((iVar5 == 0) && (pfVar7[4] != 0.0)) {
          (**(code **)(*DAT_803dd71c + 0x90))(pfVar7);
        }
      }
      *(undefined *)((int)pfVar7 + 0x116) = 10;
      FUN_80035a6c((int)param_9,(ushort)*(byte *)(*(int *)(param_9 + 0x28) + 0x62));
      if (*psVar6 == 0x72a) {
        fVar2 = FLOAT_803e5110 + pfVar7[0x1b];
      }
      else {
        fVar2 = pfVar7[0x1b];
      }
      dVar10 = (double)fVar2;
      pfVar7[0x43] = FLOAT_803e5130 * FLOAT_803dc074 + pfVar7[0x43];
      *(float *)(param_9 + 8) = pfVar7[0x43] * FLOAT_803dc074 + *(float *)(param_9 + 8);
      if ((double)*(float *)(param_9 + 8) < dVar10) {
        if ((*psVar6 == 0x72a) && ((double)*(float *)(param_9 + 8) < (double)FLOAT_803e5134)) {
          iVar5 = 1;
        }
        if ((iVar5 == 0) && (FLOAT_803e5104 < pfVar7[0x43] * pfVar7[0x43])) {
          FUN_8000b4f0((uint)param_9,0x41e,6);
        }
        pfVar7[0x43] = pfVar7[0x43] * FLOAT_803e5138;
        *(float *)(param_9 + 8) =
             (float)((double)FLOAT_803e513c * dVar10 - (double)*(float *)(param_9 + 8));
      }
      *(float *)(param_9 + 6) = pfVar7[0x1a];
      *(float *)(param_9 + 10) = pfVar7[0x1c];
      iVar3 = FUN_80021884();
      *param_9 = (short)iVar3;
      if (*(char *)((int)pfVar7 + 0x115) == '\0') {
        local_30 = (double)CONCAT44(0x43300000,(int)(short)param_9[2] ^ 0x80000000);
        param_9[2] = (short)(int)-(FLOAT_803e5140 * FLOAT_803dc074 -
                                  (float)(local_30 - DOUBLE_803e5120));
        if ((short)param_9[2] < 0x3a00) {
          *(undefined *)((int)pfVar7 + 0x115) = 1;
        }
      }
      else {
        local_38 = (double)CONCAT44(0x43300000,(int)(short)param_9[2] ^ 0x80000000);
        param_9[2] = (short)(int)(FLOAT_803e5140 * FLOAT_803dc074 +
                                 (float)(local_38 - DOUBLE_803e5120));
        if (0x5000 < (short)param_9[2]) {
          *(undefined *)((int)pfVar7 + 0x115) = 0;
        }
      }
      dVar10 = DOUBLE_803e5120;
      dVar9 = (double)(FLOAT_803e5144 * FLOAT_803dc074);
      dVar8 = (double)pfVar7[0x42];
      local_30 = (double)CONCAT44(0x43300000,(int)(short)param_9[1] ^ 0x80000000);
      iVar3 = (int)(dVar9 * dVar8 + (double)(float)(local_30 - DOUBLE_803e5120));
      local_38 = (double)(longlong)iVar3;
      param_9[1] = (short)iVar3;
      iVar3 = FUN_80036974((int)param_9,local_40,&iStack_44,&uStack_48);
      if ((((iVar5 != 0) || (iVar4 = FUN_8002bac4(), local_40[0] == iVar4)) || (iVar3 - 0xeU < 2))
         || (iVar3 == 0x13)) {
        if (iVar5 == 0) {
          *(undefined *)((int)pfVar7 + 0x116) = 0;
        }
        else {
          *(undefined *)((int)pfVar7 + 0x116) = 5;
        }
        FUN_80022264(0,2);
        FUN_801a633c(dVar10,dVar8,dVar9,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
      }
    }
    else {
      pfVar7[0x44] = pfVar7[0x44] + FLOAT_803dc074;
      fVar2 = FLOAT_803e5148;
      if (FLOAT_803e5148 <= pfVar7[0x44]) {
        *(undefined *)(pfVar7 + 0x45) = 2;
        pfVar7[0x44] = pfVar7[0x44] - fVar2;
      }
    }
  }
  else if (bVar1 < 4) {
    pfVar7[0x44] = pfVar7[0x44] + FLOAT_803dc074;
    if ((double)FLOAT_803e514c <= (double)pfVar7[0x44]) {
      FUN_8002cc9c((double)pfVar7[0x44],param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9);
      return;
    }
  }
  if (*(char *)((int)pfVar7 + 0x116) == '\0') {
    FUN_80035ff8((int)param_9);
    FUN_80035eec((int)param_9,*(undefined *)((int)pfVar7 + 0x116),0,0);
  }
  else {
    FUN_80036018((int)param_9);
    FUN_80035eec((int)param_9,*(undefined *)((int)pfVar7 + 0x116),1,0);
  }
  return;
}

