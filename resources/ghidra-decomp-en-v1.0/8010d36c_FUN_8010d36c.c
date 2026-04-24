// Function: FUN_8010d36c
// Entry: 8010d36c
// Size: 1188 bytes

void FUN_8010d36c(short *param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  double dVar6;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  float local_bc;
  undefined4 local_b8;
  float local_b4;
  undefined auStack176 [112];
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  undefined4 local_18;
  uint uStack20;
  
  psVar5 = *(short **)(param_1 + 0x52);
  if (*(short *)(DAT_803dd578 + 0xb) != 0) {
    *(ushort *)(DAT_803dd578 + 0xb) = *(short *)(DAT_803dd578 + 0xb) - (ushort)DAT_803db410;
    if (*(short *)(DAT_803dd578 + 0xb) < 0) {
      *(undefined2 *)(DAT_803dd578 + 0xb) = 0;
    }
    uStack60 = (int)*(short *)((int)DAT_803dd578 + 0x2e) - (int)*(short *)(DAT_803dd578 + 0xb) ^
               0x80000000;
    local_40 = 0x43300000;
    uStack52 = (int)*(short *)((int)DAT_803dd578 + 0x2e) ^ 0x80000000;
    local_38 = 0x43300000;
    fVar1 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1990) /
            (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1990);
    uStack36 = (uint)*(ushort *)((int)DAT_803dd578 + 0x32);
    uStack44 = *(ushort *)(DAT_803dd578 + 0xd) - uStack36 ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = 0x43300000;
    *(short *)(DAT_803dd578 + 0xc) =
         (short)(int)(fVar1 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1990) +
                     (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e1998));
    *DAT_803dd578 = fVar1 * (DAT_803dd578[6] - DAT_803dd578[5]) + DAT_803dd578[5];
    DAT_803dd578[3] = fVar1 * (DAT_803dd578[8] - DAT_803dd578[7]) + DAT_803dd578[7];
    DAT_803dd578[4] = fVar1 * (DAT_803dd578[10] - DAT_803dd578[9]) + DAT_803dd578[9];
  }
  local_d0 = *(float *)(psVar5 + 0xe) + DAT_803dd578[4];
  fVar2 = *(float *)(psVar5 + 0xe) + DAT_803dd578[3];
  fVar1 = *(float *)(param_1 + 0xe);
  if (fVar2 <= fVar1) {
    if (fVar1 <= local_d0) {
      local_d0 = FLOAT_803e19a0;
    }
    else {
      local_d0 = local_d0 - fVar1;
    }
  }
  else {
    local_d0 = fVar2 - fVar1;
  }
  local_d0 = local_d0 * DAT_803dd578[2] * FLOAT_803db414;
  *(float *)(param_1 + 0xe) = *(float *)(param_1 + 0xe) + local_d0;
  local_d8 = (*DAT_803dd578 - DAT_803dd578[1]) * FLOAT_803e19a4 * FLOAT_803db414;
  DAT_803dd578[1] = DAT_803dd578[1] + local_d8;
  local_20 = (double)CONCAT44(0x43300000,(int)*psVar5 ^ 0x80000000);
  dVar6 = (double)FUN_80293e80((double)((FLOAT_803e19ac * (float)(local_20 - DOUBLE_803e1990)) /
                                       FLOAT_803e19b0));
  local_bc = (float)((double)FLOAT_803e19a8 * dVar6 + (double)*(float *)(psVar5 + 0xc));
  local_b8 = *(undefined4 *)(psVar5 + 0xe);
  uStack36 = (int)*psVar5 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar6 = (double)FUN_80294204((double)((FLOAT_803e19ac *
                                        (float)((double)CONCAT44(0x43300000,uStack36) -
                                               DOUBLE_803e1990)) / FLOAT_803e19b0));
  local_b4 = (float)((double)FLOAT_803e19a8 * dVar6 + (double)*(float *)(psVar5 + 0x10));
  uStack44 = (int)*psVar5 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar6 = (double)FUN_80293e80((double)((FLOAT_803e19ac *
                                        (float)((double)CONCAT44(0x43300000,uStack44) -
                                               DOUBLE_803e1990)) / FLOAT_803e19b0));
  *(float *)(param_1 + 0xc) = (float)((double)DAT_803dd578[1] * dVar6 + (double)local_bc);
  uStack52 = (int)*psVar5 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar6 = (double)FUN_80294204((double)((FLOAT_803e19ac *
                                        (float)((double)CONCAT44(0x43300000,uStack52) -
                                               DOUBLE_803e1990)) / FLOAT_803e19b0));
  *(float *)(param_1 + 0x10) = (float)((double)DAT_803dd578[1] * dVar6 + (double)local_b4);
  FUN_80103524((double)FLOAT_803e19b4,&local_bc,param_1 + 0xc,&local_c8,auStack176,3,1,1);
  *(undefined4 *)(param_1 + 0xc) = local_c8;
  *(undefined4 *)(param_1 + 0xe) = local_c4;
  *(undefined4 *)(param_1 + 0x10) = local_c0;
  uStack60 = (uint)*(ushort *)(DAT_803dd578 + 0xc);
  local_40 = 0x43300000;
  (**(code **)(*DAT_803dca50 + 0x38))
            ((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1998),param_1,
             &local_cc,&local_d0,&local_d4,&local_d8,0);
  uVar3 = FUN_800217c0((double)local_cc,(double)local_d4);
  iVar4 = (0x8000 - (uVar3 & 0xffff)) - ((int)*param_1 & 0xffffU);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *param_1 = *param_1 + (short)iVar4;
  uStack20 = (uint)*(ushort *)(DAT_803dd578 + 0xc);
  local_18 = 0x43300000;
  local_d0 = *(float *)(param_1 + 0xe) -
             (*(float *)(psVar5 + 0xe) +
             (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e1998));
  uVar3 = FUN_800217c0((double)local_d0,(double)local_d8);
  iVar4 = (uVar3 & 0xffff) - ((int)param_1[1] & 0xffffU);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  iVar4 = iVar4 * (uint)DAT_803db410;
  param_1[1] = param_1[1] +
               ((short)((ulonglong)((longlong)iVar4 * 0x2aaaaaab) >> 0x20) -
               ((short)((short)(iVar4 / 0x60000) + (short)(iVar4 >> 0x1f)) >> 0xf));
  FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
               *(undefined4 *)(param_1 + 0x18));
  return;
}

