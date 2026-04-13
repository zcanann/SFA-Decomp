// Function: FUN_801f74dc
// Entry: 801f74dc
// Size: 1100 bytes

/* WARNING: Removing unreachable block (ram,0x801f7908) */
/* WARNING: Removing unreachable block (ram,0x801f7900) */
/* WARNING: Removing unreachable block (ram,0x801f78f8) */
/* WARNING: Removing unreachable block (ram,0x801f78f0) */
/* WARNING: Removing unreachable block (ram,0x801f7504) */
/* WARNING: Removing unreachable block (ram,0x801f74fc) */
/* WARNING: Removing unreachable block (ram,0x801f74f4) */
/* WARNING: Removing unreachable block (ram,0x801f74ec) */

void FUN_801f74dc(ushort *param_1)

{
  float fVar1;
  short *psVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  ushort local_70 [4];
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  
  local_7c = DAT_802c2c68;
  local_78 = DAT_802c2c6c;
  local_74 = DAT_802c2c70;
  local_88 = DAT_802c2c74;
  local_84 = DAT_802c2c78;
  local_80 = DAT_802c2c7c;
  *param_1 = *param_1 + 400;
  local_64 = FLOAT_803e6bb8;
  local_60 = FLOAT_803e6bb8;
  local_5c = FLOAT_803e6bb8;
  local_68 = FLOAT_803e6bbc;
  local_70[2] = 0;
  local_70[1] = 0;
  local_70[0] = *param_1;
  psVar2 = FUN_8000facc();
  if (psVar2 != (short *)0x0) {
    local_70[0] = 0x8000 - *psVar2;
    FUN_80021b8c(local_70,&local_88);
    dVar6 = (double)(*(float *)(param_1 + 6) - *(float *)(psVar2 + 6));
    dVar7 = (double)(*(float *)(param_1 + 8) - *(float *)(psVar2 + 8));
    dVar8 = (double)(*(float *)(param_1 + 10) - *(float *)(psVar2 + 10));
    dVar3 = FUN_80293900((double)(float)(dVar8 * dVar8 +
                                        (double)(float)(dVar6 * dVar6 +
                                                       (double)(float)(dVar7 * dVar7))));
    if ((double)FLOAT_803e6bb8 != dVar3) {
      dVar6 = (double)(float)(dVar6 / dVar3);
      dVar7 = (double)(float)(dVar7 / dVar3);
      dVar8 = (double)(float)(dVar8 / dVar3);
    }
    dVar5 = (double)local_80;
    dVar4 = (double)local_88;
    dVar3 = (double)local_84;
    dVar9 = (double)(float)(dVar8 * dVar5 +
                           (double)(float)(dVar6 * dVar4 + (double)(float)(dVar7 * dVar3)));
    dVar4 = (double)(float)(dVar5 * dVar5 +
                           (double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
    dVar3 = (double)(float)((double)(float)(dVar8 * dVar8 +
                                           (double)(float)(dVar6 * dVar6 +
                                                          (double)(float)(dVar7 * dVar7))) * dVar4);
    if (dVar3 != (double)FLOAT_803e6bb8) {
      dVar4 = FUN_80293900(dVar3);
    }
    dVar3 = (double)FLOAT_803e6bb8;
    if (dVar4 != dVar3) {
      dVar3 = (double)(float)(dVar9 / dVar4);
    }
    dVar6 = (double)FLOAT_803e6bb8;
    if (dVar3 <= dVar6) {
      if ((dVar6 < (double)FLOAT_803de924) &&
         (dVar3 = -(double)(float)((double)FLOAT_803e6c00 * (double)FLOAT_803dc074 -
                                  (double)FLOAT_803de924), FLOAT_803de924 = (float)dVar3,
         dVar3 < dVar6)) {
        FLOAT_803de924 = FLOAT_803e6bb8;
      }
    }
    else {
      dVar4 = (double)(*(float *)(param_1 + 6) - *(float *)(psVar2 + 6));
      dVar8 = (double)(*(float *)(param_1 + 10) - *(float *)(psVar2 + 10));
      dVar7 = FUN_80293900((double)(float)(dVar8 * dVar8 + (double)(float)(dVar4 * dVar4 + dVar6)));
      if ((double)FLOAT_803e6bb8 != dVar7) {
        dVar4 = (double)(float)(dVar4 / dVar7);
        dVar6 = (double)(float)(dVar6 / dVar7);
        dVar8 = (double)(float)(dVar8 / dVar7);
      }
      dVar6 = (double)((local_74 * local_74 + local_7c * local_7c + local_78 * local_78) *
                      (float)(dVar8 * dVar8 +
                             (double)(float)(dVar4 * dVar4 + (double)(float)(dVar6 * dVar6))));
      if (dVar6 != (double)FLOAT_803e6bb8) {
        FUN_80293900(dVar6);
      }
      if (dVar3 <= (double)FLOAT_803e6bc0) {
        fVar1 = FLOAT_803e6bb8 - FLOAT_803de920;
        if (fVar1 <= FLOAT_803e6bf8) {
          if (fVar1 < FLOAT_803e6bfc) {
            FLOAT_803de920 = FLOAT_803dc078 * fVar1 + FLOAT_803de920;
          }
        }
        else {
          FLOAT_803de920 = FLOAT_803dc078 * fVar1 + FLOAT_803de920;
        }
        if ((FLOAT_803e6bb8 < FLOAT_803de924) &&
           (FLOAT_803de924 = -(FLOAT_803e6c00 * FLOAT_803dc074 - FLOAT_803de924),
           FLOAT_803de924 < FLOAT_803e6bb8)) {
          FLOAT_803de924 = FLOAT_803e6bb8;
        }
      }
      else {
        local_64 = (float)((double)FLOAT_803e6bc4 * dVar4);
        local_60 = FLOAT_803e6bb8;
        local_5c = (float)((double)FLOAT_803e6bc4 * dVar8);
        dVar3 = (double)FUN_802945e0();
        fVar1 = (float)(dVar3 - (double)FLOAT_803de920);
        if ((FLOAT_803e6bd4 < fVar1) || (fVar1 < FLOAT_803e6bd8)) {
          FLOAT_803de920 = FLOAT_803de920 + fVar1 / FLOAT_803dc074;
        }
        local_68 = FLOAT_803de920;
        if (FLOAT_803de920 <= FLOAT_803e6bdc) {
          FLOAT_803de924 = FLOAT_803de924 - (FLOAT_803de920 - FLOAT_803e6bdc) / FLOAT_803e6bc4;
        }
        else {
          if (FLOAT_803de924 < FLOAT_803e6be4) {
            FLOAT_803de924 = FLOAT_803de924 + (FLOAT_803de920 - FLOAT_803e6bdc) / FLOAT_803e6be0;
          }
          local_68 = FLOAT_803de920 - FLOAT_803de924;
          if (local_68 < FLOAT_803e6bdc) {
            local_68 = FLOAT_803e6bdc;
          }
        }
        FUN_80022264(0,0x1e);
        if (FLOAT_803e6bf0 < FLOAT_803de920) {
          FLOAT_803de920 = FLOAT_803de920 - FLOAT_803e6bec;
        }
      }
    }
  }
  return;
}

