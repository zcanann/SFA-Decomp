// Function: FUN_801f6ea4
// Entry: 801f6ea4
// Size: 1100 bytes

/* WARNING: Removing unreachable block (ram,0x801f72c8) */
/* WARNING: Removing unreachable block (ram,0x801f72b8) */
/* WARNING: Removing unreachable block (ram,0x801f72c0) */
/* WARNING: Removing unreachable block (ram,0x801f72d0) */

void FUN_801f6ea4(short *param_1)

{
  float fVar1;
  short *psVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f28;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  short local_70;
  undefined2 local_6e;
  undefined2 local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  local_7c = DAT_802c24e8;
  local_78 = DAT_802c24ec;
  local_74 = DAT_802c24f0;
  local_88 = DAT_802c24f4;
  local_84 = DAT_802c24f8;
  local_80 = DAT_802c24fc;
  *param_1 = *param_1 + 400;
  local_64 = FLOAT_803e5f20;
  local_60 = FLOAT_803e5f20;
  local_5c = FLOAT_803e5f20;
  local_68 = FLOAT_803e5f24;
  local_6c = 0;
  local_6e = 0;
  local_70 = *param_1;
  psVar2 = (short *)FUN_8000faac();
  if (psVar2 != (short *)0x0) {
    local_70 = -0x8000 - *psVar2;
    FUN_80021ac8(&local_70,&local_88);
    dVar7 = (double)(*(float *)(param_1 + 6) - *(float *)(psVar2 + 6));
    dVar8 = (double)(*(float *)(param_1 + 8) - *(float *)(psVar2 + 8));
    dVar9 = (double)(*(float *)(param_1 + 10) - *(float *)(psVar2 + 10));
    dVar4 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 +
                                                (double)(float)(dVar7 * dVar7 +
                                                               (double)(float)(dVar8 * dVar8))));
    if ((double)FLOAT_803e5f20 != dVar4) {
      dVar7 = (double)(float)(dVar7 / dVar4);
      dVar8 = (double)(float)(dVar8 / dVar4);
      dVar9 = (double)(float)(dVar9 / dVar4);
    }
    dVar6 = (double)local_80;
    dVar5 = (double)local_88;
    dVar4 = (double)local_84;
    dVar10 = (double)(float)(dVar9 * dVar6 +
                            (double)(float)(dVar7 * dVar5 + (double)(float)(dVar8 * dVar4)));
    dVar4 = (double)(float)(dVar6 * dVar6 +
                           (double)(float)(dVar5 * dVar5 + (double)(float)(dVar4 * dVar4)));
    if ((float)((double)(float)(dVar9 * dVar9 +
                               (double)(float)(dVar7 * dVar7 + (double)(float)(dVar8 * dVar8))) *
               dVar4) != FLOAT_803e5f20) {
      dVar4 = (double)FUN_802931a0();
    }
    dVar7 = (double)FLOAT_803e5f20;
    if (dVar4 != dVar7) {
      dVar7 = (double)(float)(dVar10 / dVar4);
    }
    dVar4 = (double)FLOAT_803e5f20;
    if (dVar7 <= dVar4) {
      if ((dVar4 < (double)FLOAT_803ddca4) &&
         (dVar7 = -(double)(float)((double)FLOAT_803e5f68 * (double)FLOAT_803db414 -
                                  (double)FLOAT_803ddca4), FLOAT_803ddca4 = (float)dVar7,
         dVar7 < dVar4)) {
        FLOAT_803ddca4 = FLOAT_803e5f20;
      }
    }
    else {
      dVar5 = (double)(*(float *)(param_1 + 6) - *(float *)(psVar2 + 6));
      dVar9 = (double)(*(float *)(param_1 + 10) - *(float *)(psVar2 + 10));
      dVar8 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 +
                                                  (double)(float)(dVar5 * dVar5 + dVar4)));
      if ((double)FLOAT_803e5f20 != dVar8) {
        dVar5 = (double)(float)(dVar5 / dVar8);
        dVar4 = (double)(float)(dVar4 / dVar8);
        dVar9 = (double)(float)(dVar9 / dVar8);
      }
      if ((local_74 * local_74 + local_7c * local_7c + local_78 * local_78) *
          (float)(dVar9 * dVar9 + (double)(float)(dVar5 * dVar5 + (double)(float)(dVar4 * dVar4)))
          != FLOAT_803e5f20) {
        FUN_802931a0();
      }
      if (dVar7 <= (double)FLOAT_803e5f28) {
        fVar1 = FLOAT_803e5f20 - FLOAT_803ddca0;
        if (fVar1 <= FLOAT_803e5f60) {
          if (fVar1 < FLOAT_803e5f64) {
            FLOAT_803ddca0 = FLOAT_803db418 * fVar1 + FLOAT_803ddca0;
          }
        }
        else {
          FLOAT_803ddca0 = FLOAT_803db418 * fVar1 + FLOAT_803ddca0;
        }
        if ((FLOAT_803e5f20 < FLOAT_803ddca4) &&
           (FLOAT_803ddca4 = -(FLOAT_803e5f68 * FLOAT_803db414 - FLOAT_803ddca4),
           FLOAT_803ddca4 < FLOAT_803e5f20)) {
          FLOAT_803ddca4 = FLOAT_803e5f20;
        }
      }
      else {
        local_64 = (float)((double)FLOAT_803e5f2c * dVar5);
        local_60 = FLOAT_803e5f20;
        local_5c = (float)((double)FLOAT_803e5f2c * dVar9);
        dVar4 = (double)FUN_80293e80((double)((FLOAT_803e5f30 *
                                              FLOAT_803e5f34 *
                                              (float)(dVar7 - (double)FLOAT_803e5f28)) /
                                             FLOAT_803e5f38));
        fVar1 = (float)(dVar4 - (double)FLOAT_803ddca0);
        if ((FLOAT_803e5f3c < fVar1) || (fVar1 < FLOAT_803e5f40)) {
          FLOAT_803ddca0 = FLOAT_803ddca0 + fVar1 / FLOAT_803db414;
        }
        local_68 = FLOAT_803ddca0;
        if (FLOAT_803ddca0 <= FLOAT_803e5f44) {
          FLOAT_803ddca4 = FLOAT_803ddca4 - (FLOAT_803ddca0 - FLOAT_803e5f44) / FLOAT_803e5f2c;
        }
        else {
          if (FLOAT_803ddca4 < FLOAT_803e5f4c) {
            FLOAT_803ddca4 = FLOAT_803ddca4 + (FLOAT_803ddca0 - FLOAT_803e5f44) / FLOAT_803e5f48;
          }
          local_68 = FLOAT_803ddca0 - FLOAT_803ddca4;
          if (local_68 < FLOAT_803e5f44) {
            local_68 = FLOAT_803e5f44;
          }
        }
        FUN_800221a0(0,0x1e);
        if (FLOAT_803e5f58 < FLOAT_803ddca0) {
          FLOAT_803ddca0 = FLOAT_803ddca0 - FLOAT_803e5f54;
        }
      }
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  __psq_l0(auStack56,uVar3);
  __psq_l1(auStack56,uVar3);
  return;
}

