// Function: FUN_801885c0
// Entry: 801885c0
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x80188770) */

void FUN_801885c0(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  float *pfVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  int local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  sVar1 = *(short *)(param_1 + 0x46);
  if (((sVar1 == 0x7a1) || (sVar1 == 0x7a2)) || (sVar1 == 0x7a3)) {
    pfVar7 = *(float **)(param_1 + 0xb8);
    piVar5 = (int *)FUN_80036f50(2,&local_38);
    for (; local_38 != 0; local_38 = local_38 + -1) {
      dVar9 = (double)FUN_80021704(*piVar5 + 0x18,param_1 + 0x18);
      if (dVar9 < (double)pfVar7[6]) {
        iVar6 = *(int *)(*piVar5 + 0x54);
        if (iVar6 != 0) {
          uStack36 = (int)*(short *)(iVar6 + 0x5a) ^ 0x80000000;
          local_28 = 0x43300000;
          dVar9 = (double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e3b80);
          FUN_8002b2ac(&local_34,param_1,*piVar5 + 0xc);
          if (pfVar7[3] <= local_34) {
            fVar2 = FLOAT_803e3b7c;
            if (*pfVar7 < local_34) {
              fVar2 = local_34 - *pfVar7;
              fVar2 = fVar2 * fVar2;
            }
          }
          else {
            fVar2 = local_34 - pfVar7[3];
            fVar2 = fVar2 * fVar2;
          }
          if (pfVar7[4] <= local_30) {
            fVar3 = FLOAT_803e3b7c;
            if (pfVar7[1] < local_30) {
              fVar3 = local_30 - pfVar7[1];
              fVar3 = fVar3 * fVar3;
            }
          }
          else {
            fVar3 = local_30 - pfVar7[4];
            fVar3 = fVar3 * fVar3;
          }
          if (pfVar7[5] <= local_2c) {
            fVar4 = FLOAT_803e3b7c;
            if (pfVar7[2] < local_2c) {
              fVar4 = local_2c - pfVar7[2];
              fVar4 = fVar4 * fVar4;
            }
          }
          else {
            fVar4 = local_2c - pfVar7[5];
            fVar4 = fVar4 * fVar4;
          }
          if (FLOAT_803e3b7c + fVar2 + fVar3 + fVar4 < (float)(dVar9 * dVar9)) {
            *(int *)(*(int *)(*piVar5 + 0x54) + 0x50) = param_1;
            *(undefined *)(*(int *)(*piVar5 + 0x54) + 0xad) = 1;
          }
        }
      }
      piVar5 = piVar5 + 1;
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  return;
}

