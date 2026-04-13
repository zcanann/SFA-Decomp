// Function: FUN_80110980
// Entry: 80110980
// Size: 1168 bytes

/* WARNING: Removing unreachable block (ram,0x80110df4) */
/* WARNING: Removing unreachable block (ram,0x80110dec) */
/* WARNING: Removing unreachable block (ram,0x80110de4) */
/* WARNING: Removing unreachable block (ram,0x80110ddc) */
/* WARNING: Removing unreachable block (ram,0x80110dd4) */
/* WARNING: Removing unreachable block (ram,0x80110dcc) */
/* WARNING: Removing unreachable block (ram,0x80110dc4) */
/* WARNING: Removing unreachable block (ram,0x80110dbc) */
/* WARNING: Removing unreachable block (ram,0x801109c8) */
/* WARNING: Removing unreachable block (ram,0x801109c0) */
/* WARNING: Removing unreachable block (ram,0x801109b8) */
/* WARNING: Removing unreachable block (ram,0x801109b0) */
/* WARNING: Removing unreachable block (ram,0x801109a8) */
/* WARNING: Removing unreachable block (ram,0x801109a0) */
/* WARNING: Removing unreachable block (ram,0x80110998) */
/* WARNING: Removing unreachable block (ram,0x80110990) */

void FUN_80110980(short *param_1)

{
  float fVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  int local_c8;
  int local_c4 [3];
  undefined4 local_b8;
  uint uStack_b4;
  longlong local_b0;
  undefined4 local_a8;
  uint uStack_a4;
  undefined4 local_a0;
  uint uStack_9c;
  longlong local_98;
  
  if (*(char *)((int)DAT_803de238 + 0xd) == '\0') {
    if (DAT_803de238[1] == 0) {
      iVar4 = FUN_8002e1f4(local_c4,&local_c8);
      for (; local_c4[0] < local_c8; local_c4[0] = local_c4[0] + 1) {
        iVar5 = *(int *)(iVar4 + local_c4[0] * 4);
        if (*(short *)(iVar5 + 0x46) == 0x2ab) {
          DAT_803de238[1] = iVar5;
        }
        else if (*(short *)(iVar5 + 0x46) == 0x4dc) {
          *DAT_803de238 = iVar5;
        }
      }
    }
    if (DAT_803de238[2] == 0) {
      iVar4 = FUN_8002bac4();
      DAT_803de238[2] = iVar4;
    }
    iVar5 = DAT_803de238[1];
    iVar4 = *DAT_803de238;
    dVar8 = (double)(*(float *)(iVar5 + 0x18) - *(float *)(iVar4 + 0x18));
    dVar7 = (double)(*(float *)(iVar5 + 0x1c) - *(float *)(iVar4 + 0x1c));
    dVar6 = (double)(*(float *)(iVar5 + 0x20) - *(float *)(iVar4 + 0x20));
    dVar10 = (double)(float)(dVar6 * dVar6);
    dVar9 = (double)(float)(dVar8 * dVar8);
    dVar7 = FUN_80293900((double)(float)(dVar10 + (double)(float)(dVar7 * dVar7 + dVar9)));
    dVar8 = (double)(float)(dVar8 / dVar7);
    dVar6 = (double)(float)(dVar6 / dVar7);
    fVar1 = -(float)((double)FLOAT_803e27c0 * dVar8 - (double)*(float *)(*DAT_803de238 + 0x18)) -
            *(float *)(DAT_803de238[2] + 0x18);
    fVar2 = -(float)((double)FLOAT_803e27c0 * dVar6 - (double)*(float *)(*DAT_803de238 + 0x20)) -
            *(float *)(DAT_803de238[2] + 0x20);
    dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    fVar1 = (float)((double)(float)((double)FLOAT_803e27c4 - dVar7) / (double)FLOAT_803e27c4);
    *(float *)(param_1 + 0x5a) = FLOAT_803e27cc * fVar1 + FLOAT_803e27c8;
    dVar7 = (double)(FLOAT_803e27d4 * fVar1 + FLOAT_803e27d0);
    *(float *)(param_1 + 0xc) = -(float)(dVar8 * dVar7 - (double)*(float *)(*DAT_803de238 + 0x18));
    *(float *)(param_1 + 0xe) =
         FLOAT_803e27dc * fVar1 + FLOAT_803e27d8 + *(float *)(*DAT_803de238 + 0x1c);
    *(float *)(param_1 + 0x10) = -(float)(dVar6 * dVar7 - (double)*(float *)(*DAT_803de238 + 0x20));
    iVar4 = FUN_80021884();
    *param_1 = -(short)iVar4;
    FUN_80293900((double)(float)(dVar9 + dVar10));
    iVar4 = FUN_80021884();
    param_1[1] = -(short)iVar4;
    if (*(char *)(DAT_803de238 + 3) == '\0') {
      fVar1 = (float)DAT_803de238[4] / FLOAT_803e27dc;
      *(float *)(param_1 + 0xc) =
           fVar1 * ((float)DAT_803de238[5] - *(float *)(param_1 + 0xc)) + *(float *)(param_1 + 0xc);
      *(float *)(param_1 + 0xe) =
           fVar1 * ((float)DAT_803de238[6] - *(float *)(param_1 + 0xe)) + *(float *)(param_1 + 0xe);
      *(float *)(param_1 + 0x10) =
           fVar1 * ((float)DAT_803de238[7] - *(float *)(param_1 + 0x10)) +
           *(float *)(param_1 + 0x10);
      sVar3 = *(short *)(DAT_803de238 + 8) - *param_1;
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      local_c4[2] = (int)sVar3 ^ 0x80000000;
      local_c4[1] = 0x43300000;
      uStack_b4 = (int)*param_1 ^ 0x80000000;
      local_b8 = 0x43300000;
      iVar4 = (int)((float)((double)CONCAT44(0x43300000,local_c4[2]) - DOUBLE_803e27f0) * fVar1 +
                   (float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e27f0));
      local_b0 = (longlong)iVar4;
      *param_1 = (short)iVar4;
      sVar3 = *(short *)((int)DAT_803de238 + 0x22) - param_1[1];
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      uStack_a4 = (int)sVar3 ^ 0x80000000;
      local_a8 = 0x43300000;
      uStack_9c = (int)param_1[1] ^ 0x80000000;
      local_a0 = 0x43300000;
      iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e27f0) * fVar1 +
                   (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e27f0));
      local_98 = (longlong)iVar4;
      param_1[1] = (short)iVar4;
      DAT_803de238[4] = (int)((float)DAT_803de238[4] - FLOAT_803dc074);
      fVar1 = FLOAT_803e27e8;
      if ((float)DAT_803de238[4] < FLOAT_803e27e8) {
        *(undefined *)(DAT_803de238 + 3) = 1;
        DAT_803de238[4] = (int)fVar1;
      }
    }
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

