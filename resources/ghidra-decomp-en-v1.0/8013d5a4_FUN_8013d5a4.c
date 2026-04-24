// Function: FUN_8013d5a4
// Entry: 8013d5a4
// Size: 844 bytes

/* WARNING: Removing unreachable block (ram,0x8013d8c0) */
/* WARNING: Removing unreachable block (ram,0x8013d8b8) */
/* WARNING: Removing unreachable block (ram,0x8013d8c8) */

void FUN_8013d5a4(double param_1,short *param_2,int param_3,float *param_4,char param_5)

{
  float fVar1;
  float fVar2;
  int iVar3;
  float *pfVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f29;
  double dVar7;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  short local_58;
  undefined2 local_56;
  undefined2 local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  fVar1 = *(float *)(param_3 + 0x14);
  fVar2 = FLOAT_803e2420;
  while( true ) {
    dVar6 = (double)fVar1;
    if (dVar6 <= (double)FLOAT_803e23dc) break;
    fVar2 = (float)(dVar6 * (double)FLOAT_803db414 + (double)fVar2);
    fVar1 = (float)(dVar6 + (double)(float)((double)FLOAT_803e241c * (double)FLOAT_803db414));
  }
  dVar7 = (double)(float)(param_1 + (double)fVar2);
  dVar9 = (double)(float)(dVar7 * dVar7);
  dVar6 = (double)FUN_8002166c(param_4,param_2 + 0xc);
  if (dVar9 <= dVar6) {
    if (param_5 != '\0') {
      local_50 = *param_4 - *(float *)(param_2 + 0xc);
      local_4c = param_4[1] - *(float *)(param_2 + 0xe);
      local_48 = param_4[2] - *(float *)(param_2 + 0x10);
      local_58 = -*param_2;
      local_56 = 0;
      local_54 = 0;
      FUN_80021ac8(&local_58,&local_50);
      if (FLOAT_803e23dc < local_48) {
        fVar1 = FLOAT_803e241c * FLOAT_803db414 + *(float *)(param_3 + 0x14);
        if (fVar1 < FLOAT_803e23dc) {
          fVar1 = FLOAT_803e23dc;
        }
        *(float *)(param_3 + 0x14) = fVar1;
        goto LAB_8013d8b8;
      }
    }
    if ((*(uint *)(param_3 + 0x54) & 0x10000000) == 0) {
      dVar7 = (double)((float)((double)FLOAT_803e2488 + dVar7) *
                      (float)((double)FLOAT_803e2488 + dVar7));
      iVar3 = *(int *)(param_2 + 0x5c);
      pfVar4 = *(float **)(iVar3 + 0x28);
      fVar1 = FLOAT_803e23dc;
      if (pfVar4 == *(float **)(iVar3 + 0x6f0)) {
        fVar1 = *(float *)(iVar3 + 0x6f4) - *(float *)(param_2 + 0xc);
        fVar2 = *(float *)(iVar3 + 0x6fc) - *(float *)(param_2 + 0x10);
        dVar9 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
        dVar8 = (double)(float)((double)FLOAT_803db418 * dVar9);
        dVar9 = (double)FUN_802931a0((double)((*pfVar4 - *(float *)(param_2 + 0xc)) *
                                              (*pfVar4 - *(float *)(param_2 + 0xc)) +
                                             (pfVar4[2] - *(float *)(param_2 + 0x10)) *
                                             (pfVar4[2] - *(float *)(param_2 + 0x10))));
        fVar1 = (float)((double)(float)((double)FLOAT_803db418 * dVar9) - dVar8);
      }
      if ((dVar7 <= dVar6) || (fVar1 <= FLOAT_803e23dc)) {
        if ((*(uint *)(param_3 + 0x54) & 0x100000) == 0) {
          fVar1 = FLOAT_803e2420 * FLOAT_803db414 + *(float *)(param_3 + 0x14);
          if (FLOAT_803e248c < fVar1) {
            fVar1 = FLOAT_803e248c;
          }
          *(float *)(param_3 + 0x14) = fVar1;
        }
        else {
          *(float *)(param_3 + 0x14) = FLOAT_803e243c * FLOAT_803db414 + *(float *)(param_3 + 0x14);
          if (FLOAT_803e248c < *(float *)(param_3 + 0x14)) {
            *(float *)(param_3 + 0x14) = FLOAT_803e248c;
          }
        }
      }
      else {
        fVar2 = *(float *)(param_3 + 0x14);
        if (fVar2 <= fVar1) {
          if (fVar1 <= FLOAT_803e248c) {
            fVar2 = FLOAT_803e2420 * FLOAT_803db414 + fVar2;
            if (fVar1 < fVar2) {
              fVar2 = fVar1;
            }
            *(float *)(param_3 + 0x14) = fVar2;
          }
          else {
            fVar2 = FLOAT_803e2420 * FLOAT_803db414 + fVar2;
            if (FLOAT_803e248c < fVar2) {
              fVar2 = FLOAT_803e248c;
            }
            *(float *)(param_3 + 0x14) = fVar2;
          }
        }
        else {
          fVar2 = FLOAT_803e241c * FLOAT_803db414 + fVar2;
          if (fVar2 < fVar1) {
            fVar2 = fVar1;
          }
          *(float *)(param_3 + 0x14) = fVar2;
        }
      }
    }
    else {
      *(float *)(param_3 + 0x14) = FLOAT_803e23f4 * FLOAT_803db414 + *(float *)(param_3 + 0x14);
      if (*(float *)(param_3 + 0x14) < FLOAT_803e23dc) {
        *(float *)(param_3 + 0x14) = FLOAT_803e23dc;
      }
    }
  }
  else {
    fVar1 = FLOAT_803e241c * FLOAT_803db414 + *(float *)(param_3 + 0x14);
    if (fVar1 < FLOAT_803e23dc) {
      fVar1 = FLOAT_803e23dc;
    }
    *(float *)(param_3 + 0x14) = fVar1;
  }
LAB_8013d8b8:
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  return;
}

