// Function: FUN_801b4dbc
// Entry: 801b4dbc
// Size: 2124 bytes

/* WARNING: Removing unreachable block (ram,0x801b55e8) */
/* WARNING: Removing unreachable block (ram,0x801b53a8) */
/* WARNING: Removing unreachable block (ram,0x801b4dcc) */

void FUN_801b4dbc(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  short sVar2;
  uint uVar3;
  float *pfVar4;
  float fVar5;
  uint uVar6;
  float fVar7;
  int iVar8;
  float *pfVar9;
  int iVar10;
  float *pfVar11;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps31_1;
  undefined local_e8;
  undefined local_e7;
  undefined local_e6;
  float local_e4;
  float local_e0;
  float local_dc;
  short local_d8;
  short local_d6;
  short local_d4;
  short local_d2;
  short local_d0;
  short local_ce;
  float afStack_cc [12];
  undefined auStack_9c [8];
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_60;
  float fStack_5c;
  undefined4 local_58;
  float fStack_54;
  undefined4 local_50;
  float fStack_4c;
  undefined8 local_48;
  undefined4 local_40;
  float fStack_3c;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar3 = FUN_8028683c();
  pfVar9 = *(float **)(uVar3 + 0xb8);
  DAT_803de7d8 = DAT_803de7d8 + 1;
  pfVar9[0x293] = (float)((int)pfVar9[0x293] + (uint)DAT_803dc070);
  pfVar11 = pfVar9;
  for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(pfVar9 + 0x296); iVar10 = iVar10 + 1) {
    pfVar11[4] = (float)((int)pfVar11[4] + (uint)DAT_803dc070);
    if (*(char *)((int)pfVar11 + 0x2f) != '\0') {
      dVar13 = (double)pfVar11[7];
      param_3 = (double)FLOAT_803e55cc;
      fStack_5c = -pfVar11[5];
      local_60 = 0x43300000;
      fStack_54 = -pfVar11[4];
      local_58 = 0x43300000;
      local_50 = 0x43300000;
      fStack_4c = fStack_5c;
      dVar12 = (double)FUN_80292538();
      pfVar11[3] = -(float)((double)FLOAT_803de7f0 *
                            (double)(float)((double)(float)(dVar13 - (double)pfVar11[6]) * dVar12) -
                           dVar13);
      local_48 = (double)CONCAT44(0x43300000,-pfVar11[4]);
      fStack_3c = -pfVar11[5];
      local_40 = 0x43300000;
      dVar12 = (double)FUN_80292538();
      param_2 = (double)FLOAT_803e55d0;
      iVar8 = (int)-(float)((double)FLOAT_803de7ec * (double)(float)(param_2 * dVar12) - param_2);
      local_38 = (double)(longlong)iVar8;
      *(char *)((int)pfVar11 + 0x2e) = (char)iVar8;
      if ((int)pfVar11[4] < (int)pfVar11[5]) {
        *(ushort *)(pfVar11 + 10) =
             *(short *)(pfVar11 + 10) + (ushort)DAT_803dc070 * *(short *)((int)pfVar11 + 0x2a);
        if (3 < *(byte *)(pfVar11 + 0xb)) {
          *(byte *)(pfVar11 + 0xb) = *(byte *)(pfVar11 + 0xb) - 4;
        }
        dVar12 = DOUBLE_803e55e0;
        if (*(byte *)((int)pfVar11 + 0x2d) < 5) {
          local_38 = (double)CONCAT44(0x43300000,-pfVar11[4]);
          fStack_3c = -pfVar11[5];
          local_40 = 0x43300000;
          param_2 = dVar12;
          if (((float)(local_38 - DOUBLE_803e55e0) /
               (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e55e0) < FLOAT_803e5630)
             && (pfVar11[8] = (float)((int)pfVar11[8] - (uint)DAT_803dc070), (int)pfVar11[8] < 1)) {
            dVar12 = (double)pfVar11[7];
            iVar8 = *(int *)(uVar3 + 0xb8);
            uVar6 = FUN_80022264(0xfffffffb,3);
            local_38 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
            param_2 = (double)(float)(local_38 - DOUBLE_803e55e0);
            local_e4 = pfVar11[3] *
                       (float)((double)FLOAT_803e55f4 * param_2 + (double)FLOAT_803e55c4);
            local_e0 = FLOAT_803e55f8;
            local_dc = FLOAT_803e55f8;
            fStack_3c = (float)FUN_80022264(0,0xffff);
            fStack_3c = -fStack_3c;
            local_40 = 0x43300000;
            FUN_8024782c((double)(float)(DOUBLE_803e5600 *
                                        (double)((float)((double)CONCAT44(0x43300000,fStack_3c) -
                                                        DOUBLE_803e55e0) / FLOAT_803e5608)),
                         afStack_cc,0x7a);
            pfVar4 = (float *)FUN_8000f560();
            FUN_80247618(pfVar4,afStack_cc,afStack_cc);
            FUN_80247cd8(afStack_cc,&local_e4,&local_e4);
            local_e4 = local_e4 + *pfVar11;
            local_e0 = local_e0 + pfVar11[1];
            local_dc = local_dc + pfVar11[2];
            uVar6 = FUN_80022264(0xc0,0x100);
            local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
            if (*(byte *)(iVar8 + 0xa58) < 0x32) {
              param_2 = (double)local_e4;
              param_3 = (double)local_e0;
              param_4 = (double)local_dc;
              FUN_801b4398((double)((float)(dVar12 * (double)(float)(local_48 - DOUBLE_803e55e0)) *
                                   FLOAT_803e560c),param_2,param_3,param_4);
            }
            pfVar11[8] = pfVar11[9];
          }
        }
      }
      else {
        *(undefined *)((int)pfVar11 + 0x2f) = 0;
      }
    }
    pfVar11 = pfVar11 + 0xc;
  }
  dVar12 = (double)FUN_80003494((uint)auStack_9c,uVar3,0x38);
  local_94 = FLOAT_803e55c4;
  local_78 = FLOAT_803e55f8;
  local_74 = FLOAT_803e55f8;
  local_70 = FLOAT_803e55f8;
  pfVar11 = pfVar9;
  for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)((int)pfVar9 + 0xa5a); iVar10 = iVar10 + 1) {
    dVar13 = param_4;
    if (*(char *)(pfVar11 + 0x261) != '\0') {
      pfVar11[0x25f] = (float)((int)pfVar11[0x25f] + (uint)DAT_803dc070);
      dVar13 = DOUBLE_803e5628;
      if ((int)pfVar11[0x25f] < (int)pfVar11[0x260]) {
        uVar6 = (uint)DAT_803dc070;
        local_38 = (double)CONCAT44(0x43300000,uVar6);
        param_5 = (double)pfVar11[0x25d];
        param_6 = -(double)(float)((double)pfVar9[0x28f] *
                                   (double)(float)(local_38 - DOUBLE_803e5628) - param_5);
        param_3 = (double)FLOAT_803e5634;
        fStack_3c = -(float)(uVar6 * uVar6);
        local_40 = 0x43300000;
        local_48 = (double)CONCAT44(0x43300000,uVar6);
        pfVar11[0x25a] =
             -(float)(param_3 * (double)(float)((double)pfVar9[0x28f] *
                                               (double)(float)((double)CONCAT44(0x43300000,fStack_3c
                                                                               ) - DOUBLE_803e55e0))
                     - (double)(float)(param_5 * (double)(float)(local_48 - DOUBLE_803e5628) +
                                      (double)pfVar11[0x25a]));
        pfVar11[0x25d] = (float)param_6;
        fStack_4c = (float)(uint)DAT_803dc070;
        local_50 = 0x43300000;
        pfVar11[0x259] =
             pfVar11[0x25c] * (float)((double)CONCAT44(0x43300000,fStack_4c) - dVar13) +
             pfVar11[0x259];
        fStack_54 = (float)(uint)DAT_803dc070;
        local_58 = 0x43300000;
        pfVar11[0x25b] =
             pfVar11[0x25e] * (float)((double)CONCAT44(0x43300000,fStack_54) - dVar13) +
             pfVar11[0x25b];
        if (((*(char *)(pfVar9 + 0x297) != '\0') && (pfVar11[0x25a] < pfVar9[600])) &&
           (pfVar11[0x25d] < FLOAT_803e55f8)) {
          pfVar11[0x25d] = FLOAT_803e5638 * -pfVar11[0x25d];
        }
        local_90 = pfVar11[0x259];
        param_2 = (double)local_90;
        local_8c = pfVar11[0x25a];
        dVar12 = (double)local_8c;
        local_88 = pfVar11[0x25b];
        local_84 = local_90;
        local_80 = local_8c;
        local_7c = local_88;
        if ((DAT_803de7d8 & 1) != 0) {
          fVar5 = pfVar11[0x25f];
          if ((int)fVar5 < 0x40) {
            local_d0 = (short)((int)fVar5 << 6);
            local_d8 = -1 - local_d0;
            local_d4 = -0x8000;
            local_d2 = -0x4000 - local_d0;
            local_d0 = -0x6000 - local_d0;
            local_d6 = local_d8;
          }
          else if ((int)fVar5 < 0x80) {
            local_d6 = (short)((int)fVar5 << 6);
            local_d8 = -0x4000 - local_d6;
            local_d6 = -0x6000 - local_d6;
            local_d4 = 0;
            local_d2 = -0x8000;
            local_d0 = 0;
          }
          else {
            local_d8 = -0x6000;
            local_d6 = 0;
            local_d4 = 0;
            local_d2 = 0;
            local_d0 = 0;
          }
          sVar2 = local_d4;
          local_ce = 0;
          bVar1 = *(byte *)((int)pfVar9 + 0xa5d);
          if (bVar1 == 2) {
            local_d6 = local_d8;
            local_d0 = local_d2;
            local_d8 = local_d4;
            local_d2 = 0;
          }
          else if (bVar1 < 2) {
            if (bVar1 != 0) {
              local_d6 = local_d4;
              local_d0 = 0;
            }
          }
          else if (bVar1 < 4) {
            local_d6 = local_d4;
            local_d0 = 0;
            local_d4 = local_d8;
            local_ce = local_d2;
            local_d8 = sVar2;
            local_d2 = 0;
          }
          dVar12 = (double)(**(code **)(*DAT_803dd708 + 8))
                                     (uVar3,0x5e,auStack_9c,0x200001,0xffffffff,&local_d8);
        }
      }
      else {
        *(undefined *)(pfVar11 + 0x261) = 0;
        dVar13 = param_4;
      }
    }
    pfVar11 = pfVar11 + 9;
    param_4 = dVar13;
  }
  fVar5 = pfVar9[0x293];
  fVar7 = pfVar9[0x294];
  if ((int)fVar7 << 1 < (int)fVar5) {
    FUN_8002cc9c(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3);
  }
  else {
    if ((int)fVar7 < (int)fVar5) {
      if (pfVar9[0x290] != 0.0) {
        FUN_8001dc30((double)FLOAT_803e55f8,(int)pfVar9[0x290],'\0');
      }
    }
    else {
      local_38 = (double)CONCAT44(0x43300000,-fVar5);
      fStack_3c = -fVar7;
      local_40 = 0x43300000;
      FUN_801b466c(*(byte *)((int)pfVar9 + 0xa5d),&local_e8);
      if (pfVar9[0x290] != 0.0) {
        FUN_8001dbb4((int)pfVar9[0x290],local_e8,local_e7,local_e6,0xff);
      }
    }
    local_38 = (double)CONCAT44(0x43300000,-pfVar9[0x293]);
    fStack_3c = -pfVar9[0x294];
    local_40 = 0x43300000;
    fVar5 = (float)(local_38 - DOUBLE_803e55e0) /
            (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e55e0);
    *(float *)(uVar3 + 8) = FLOAT_803e563c * fVar5 * pfVar9[0x295];
    iVar10 = (int)-(FLOAT_803e55d0 * fVar5 - FLOAT_803e55d0);
    local_48 = (double)(longlong)iVar10;
    *(char *)(uVar3 + 0x36) = (char)iVar10;
    if ((*(char *)((int)pfVar9 + 0xa5b) == '\0') && ((int)pfVar9[0x294] >> 1 <= (int)pfVar9[0x293]))
    {
      uVar3 = FUN_80022264(0x1000,0x6000);
      local_d8 = (short)uVar3;
      local_d2 = SUB42(pfVar9[5],0);
      uVar3 = 0;
      while (local_38 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000),
            (float)(local_38 - DOUBLE_803e55e0) < pfVar9[0x295]) {
        uVar3 = uVar3 + 1;
      }
      *(undefined *)((int)pfVar9 + 0xa5b) = 1;
      local_d6 = local_d8;
      local_d4 = local_d8;
    }
  }
  FUN_80286888();
  return;
}

