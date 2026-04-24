// Function: FUN_802ba050
// Entry: 802ba050
// Size: 980 bytes

/* WARNING: Removing unreachable block (ram,0x802ba3fc) */
/* WARNING: Removing unreachable block (ram,0x802ba3f4) */
/* WARNING: Removing unreachable block (ram,0x802ba068) */
/* WARNING: Removing unreachable block (ram,0x802ba060) */

undefined4
FUN_802ba050(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            short *param_9,uint *param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  uint uVar5;
  short *psVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  float local_58 [2];
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  
  local_58[0] = FLOAT_803e8ed8;
  iVar4 = FUN_80036f50(0x13,param_9,local_58);
  iVar9 = *(int *)(param_9 + 0x5c);
  uVar5 = FUN_80020078(0x3e3);
  if ((uVar5 != 0) &&
     (uVar5 = FUN_80022150((double)FLOAT_803e8edc,(double)FLOAT_803e8ee0,(float *)(iVar9 + 0xd04)),
     uVar5 != 0)) {
    FUN_8000bb38((uint)param_9,0x43a);
  }
  *param_10 = *param_10 | 0x200000;
  if ((float)param_10[0xa6] < FLOAT_803e8ee4) {
    *(undefined2 *)(param_10 + 0xcd) = 0;
    *(undefined2 *)((int)param_10 + 0x336) = 0;
    param_10[0xa6] = (uint)FLOAT_803e8ecc;
  }
  if (*(short *)(param_10 + 0xcd) < 0x5a) {
    dVar12 = (double)FLOAT_803e8ee8;
    uStack_4c = (int)*(short *)((int)param_10 + 0x336) ^ 0x80000000;
    local_50 = 0x43300000;
    uStack_44 = (int)*param_9 ^ 0x80000000;
    local_48 = 0x43300000;
    iVar8 = (int)(dVar12 * (double)((float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) -
                                                           DOUBLE_803e8f08) * param_1) /
                                   FLOAT_803e8eec) +
                 (double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e8f08));
    local_40 = (longlong)iVar8;
    *param_9 = (short)iVar8;
    fVar2 = (float)param_10[0xa6];
    if ((float)param_10[0xa6] < FLOAT_803e8ecc) {
      fVar2 = FLOAT_803e8ecc;
    }
    if (FLOAT_803e8ef0 < fVar2) {
      fVar2 = FLOAT_803e8ef0;
    }
    if (*(short *)(iVar9 + 0xa88) == 0) {
      fVar2 = FLOAT_803e8ecc;
    }
    dVar11 = (double)(FLOAT_803e8ef4 * fVar2);
    if ((double)(FLOAT_803e8ef4 * fVar2) < (double)FLOAT_803e8ecc) {
      dVar11 = (double)FLOAT_803e8ecc;
    }
    param_10[0xa5] =
         (uint)(float)(param_1 * (double)((float)(dVar11 - (double)(float)param_10[0xa5]) /
                                         (float)param_10[0xae]) + (double)(float)param_10[0xa5]);
    uVar5 = (uint)param_9[1];
    if ((int)uVar5 < 1) {
      uStack_44 = uVar5 ^ 0x80000000;
      local_48 = 0x43300000;
      dVar10 = (double)FUN_802945e0();
      dVar11 = (double)FLOAT_803e8f04 * dVar10 - dVar11;
    }
    else {
      local_40 = CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      dVar10 = (double)FUN_802945e0();
      dVar11 = (double)FLOAT_803e8ef8 * dVar10 - dVar11;
    }
    dVar10 = -(double)(float)dVar11;
    if (-(double)(float)dVar11 < (double)DAT_80335d90) {
      dVar10 = (double)DAT_80335d90;
    }
    param_10[0xa0] =
         (uint)(float)(param_1 * (double)((float)(dVar10 - (double)(float)param_10[0xa0]) /
                                         (float)param_10[0xae]) + (double)(float)param_10[0xa0]);
    iVar8 = 0;
    dVar11 = (double)*(float *)(param_9 + 0x4c);
    psVar6 = &DAT_803dd3b0;
    sVar1 = param_9[0x50];
    for (iVar9 = 0; (sVar1 != *psVar6 && (iVar9 < 2)); iVar9 = iVar9 + 1) {
      psVar6 = psVar6 + 1;
    }
    if (1 < iVar9) {
      iVar9 = 0;
    }
    if (sVar1 == 0x208) {
      iVar9 = 1;
    }
    dVar10 = (double)(float)param_10[0xa5];
    if ((double)(float)(&DAT_80335d88)[iVar9 * 2] <= dVar10) {
      if ((double)*(float *)(iVar9 * 8 + -0x7fcca274) <= dVar10) {
        if (iVar9 == 0) {
          dVar11 = (double)FLOAT_803e8ecc;
        }
        iVar9 = iVar9 + 1;
        iVar8 = 1;
      }
    }
    else {
      if (iVar9 == 1) {
        return 8;
      }
      iVar9 = iVar9 + -1;
      iVar8 = 1;
    }
    bVar3 = true;
    if ((*(char *)((int)param_10 + 0x346) != '\0') && (sVar1 == 0x208)) {
      iVar8 = 1;
      bVar3 = false;
    }
    if (iVar8 != 0) {
      if ((iVar9 == 1) && (bVar3)) {
        FUN_8003042c(dVar11,dVar10,dVar12,param_4,param_5,param_6,param_7,param_8,param_9,0x208,0,
                     iVar8,param_13,param_14,param_15,param_16);
      }
      else {
        FUN_8003042c(dVar11,dVar10,dVar12,param_4,param_5,param_6,param_7,param_8,param_9,
                     (int)(short)(&DAT_803dd3b0)[iVar9],0,iVar8,param_13,param_14,param_15,param_16)
        ;
      }
    }
    FUN_8002f6cc((double)(float)param_10[0xa0],(int)param_9,(float *)(param_10 + 0xa8));
    if (((param_10[199] & 0x100) == 0) || ((iVar4 != 0 && ((*(byte *)(iVar4 + 0xaf) & 4) != 0)))) {
      uVar7 = 0;
    }
    else {
      uVar7 = 0xc;
    }
  }
  else {
    uVar7 = 8;
  }
  return uVar7;
}

