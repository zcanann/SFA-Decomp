// Function: FUN_80103708
// Entry: 80103708
// Size: 584 bytes

/* WARNING: Removing unreachable block (ram,0x80103920) */
/* WARNING: Removing unreachable block (ram,0x80103928) */

undefined FUN_80103708(int param_1,short *param_2,undefined4 param_3,short *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack216 [4];
  float local_d4;
  undefined auStack208 [4];
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  undefined auStack176 [110];
  undefined local_42;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uStack60 = (int)*param_2 ^ 0x80000000;
  local_40 = 0x43300000;
  dVar7 = (double)FUN_80293e80((double)((FLOAT_803e168c *
                                        (float)((double)CONCAT44(0x43300000,uStack60) -
                                               DOUBLE_803e1698)) / FLOAT_803e1690));
  uStack52 = (int)*param_2 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar8 = (double)FUN_80294204((double)((FLOAT_803e168c *
                                        (float)((double)CONCAT44(0x43300000,uStack52) -
                                               DOUBLE_803e1698)) / FLOAT_803e1690));
  local_cc = *(float *)(DAT_803dd530 + 4) * *(float *)(DAT_803dd530 + 4) -
             *(float *)(DAT_803dd530 + 8) * *(float *)(DAT_803dd530 + 8);
  if (local_cc < FLOAT_803e1694) {
    local_cc = FLOAT_803e1694;
  }
  dVar9 = (double)FUN_802931a0((double)local_cc);
  local_cc = (float)dVar9;
  local_c8 = (float)(dVar7 * (double)(float)dVar9 + (double)*(float *)(param_2 + 0xc));
  fVar1 = *(float *)(param_2 + 0xe) + *(float *)(DAT_803dd530 + 0x8c);
  local_c4 = *(float *)(DAT_803dd530 + 8) + fVar1;
  local_c0 = (float)(dVar8 * (double)(float)dVar9 + (double)*(float *)(param_2 + 0x10));
  fVar2 = *(float *)(param_2 + 0xc);
  fVar3 = *(float *)(param_2 + 0x10);
  if (param_2[0x22] == 1) {
    FUN_80296bd4(param_2,&local_bc,&local_b8,&local_b4);
    fVar2 = local_bc;
    fVar1 = local_b8;
    fVar3 = local_b4;
  }
  local_b4 = fVar3;
  local_b8 = fVar1;
  local_bc = fVar2;
  FUN_80103524((double)FLOAT_803e1688,&local_bc,&local_c8,param_3,auStack176,3,1,1);
  (**(code **)(*DAT_803dca50 + 0x38))
            ((double)*(float *)(DAT_803dd530 + 0x8c),param_1,auStack208,&local_d4,auStack216,
             &local_cc,0);
  local_d4 = *(float *)(param_1 + 0x1c) -
             (*(float *)(param_2 + 0xe) + *(float *)(DAT_803dd530 + 0x8c));
  uVar4 = FUN_800217c0((double)local_d4,(double)local_cc);
  iVar5 = (uVar4 & 0xffff) - ((int)*(short *)(param_1 + 2) & 0xffffU);
  if (0x8000 < iVar5) {
    iVar5 = iVar5 + -0xffff;
  }
  if (iVar5 < -0x8000) {
    iVar5 = iVar5 + 0xffff;
  }
  if (param_4 != (short *)0x0) {
    *param_4 = *(short *)(param_1 + 2) + (short)iVar5;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return local_42;
}

