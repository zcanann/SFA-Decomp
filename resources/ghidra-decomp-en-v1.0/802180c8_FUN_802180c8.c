// Function: FUN_802180c8
// Entry: 802180c8
// Size: 812 bytes

/* WARNING: Removing unreachable block (ram,0x802183c8) */
/* WARNING: Removing unreachable block (ram,0x802183d0) */

void FUN_802180c8(double param_1,undefined2 *param_2,int param_3,int param_4)

{
  float fVar1;
  undefined2 uVar3;
  short sVar4;
  int iVar2;
  int *piVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 uVar8;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack120 [8];
  undefined auStack112 [8];
  undefined auStack104 [8];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  longlong local_38;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  piVar5 = *(int **)(param_2 + 0x5c);
  local_48 = *(float *)(param_4 + 0xc) - *(float *)(param_3 + 0xc);
  local_44 = *(float *)(param_4 + 0x10) - *(float *)(param_3 + 0x10);
  local_40 = *(float *)(param_4 + 0x14) - *(float *)(param_3 + 0x14);
  dVar7 = (double)FUN_802931a0((double)(local_40 * local_40 +
                                       local_48 * local_48 + local_44 * local_44));
  fVar1 = (float)(dVar7 / param_1);
  if (fVar1 != FLOAT_803e695c) {
    local_48 = local_48 / fVar1;
    local_44 = local_44 / fVar1;
    local_40 = local_40 / fVar1;
  }
  *(undefined4 *)(param_2 + 6) = *(undefined4 *)(param_3 + 0xc);
  *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x10);
  *(undefined4 *)(param_2 + 10) = *(undefined4 *)(param_3 + 0x14);
  *(float *)(param_2 + 0x12) = local_48;
  *(float *)(param_2 + 0x14) = local_44;
  *(float *)(param_2 + 0x16) = local_40;
  uVar8 = FUN_802931a0((double)(*(float *)(param_2 + 0x12) * *(float *)(param_2 + 0x12) +
                               *(float *)(param_2 + 0x16) * *(float *)(param_2 + 0x16)));
  uVar3 = FUN_800217c0((double)*(float *)(param_2 + 0x12),(double)*(float *)(param_2 + 0x16));
  *param_2 = uVar3;
  sVar4 = FUN_800217c0((double)*(float *)(param_2 + 0x14),uVar8);
  param_2[1] = -sVar4;
  param_2[2] = 0;
  FUN_80035f20(param_2);
  *(undefined *)(piVar5 + 1) = 3;
  local_60 = *(float *)(param_2 + 6) + FLOAT_803e6960 * *(float *)(param_2 + 0x12);
  local_5c = *(float *)(param_2 + 8) + FLOAT_803e6960 * *(float *)(param_2 + 0x14);
  local_58 = *(float *)(param_2 + 10) + FLOAT_803e6960 * *(float *)(param_2 + 0x16);
  FUN_80012d00(param_2 + 6,auStack104);
  FUN_80012d00(&local_60,auStack112);
  iVar2 = FUN_800128dc(auStack104,auStack112,auStack120,0,0);
  if (iVar2 == 0) {
    FUN_80012e0c(&local_60,auStack120);
    local_54 = local_60 - *(float *)(param_2 + 6);
    local_50 = local_5c - *(float *)(param_2 + 8);
    local_4c = local_58 - *(float *)(param_2 + 10);
    dVar7 = (double)FUN_802931a0((double)(local_4c * local_4c +
                                         local_54 * local_54 + local_50 * local_50));
    local_38 = (longlong)(int)(dVar7 / param_1);
    piVar5[2] = (int)(dVar7 / param_1);
  }
  else {
    piVar5[2] = 600;
  }
  if (*piVar5 != 0) {
    FUN_8001f384();
    *piVar5 = 0;
  }
  iVar2 = FUN_8001f4c8(param_2,1);
  if (iVar2 != 0) {
    FUN_8001db2c(iVar2,2);
    FUN_8001daf0(iVar2,0,0xff,0xff,0);
    FUN_8001db14(iVar2,1);
    FUN_8001dc38((double)FLOAT_803e6940,(double)FLOAT_803e6944,iVar2);
    FUN_8001d730((double)FLOAT_803e6948,iVar2,0,0,0xff,0xff,0x80);
    FUN_8001d714((double)FLOAT_803e694c,iVar2);
  }
  *piVar5 = iVar2;
  *(undefined *)(param_2 + 0x1b) = 0xff;
  *(float *)(param_2 + 4) = FLOAT_803e6958 * *(float *)(*(int *)(param_2 + 0x28) + 4);
  FUN_8000bb18(param_2,0x173);
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

