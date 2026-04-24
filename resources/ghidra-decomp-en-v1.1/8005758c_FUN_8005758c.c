// Function: FUN_8005758c
// Entry: 8005758c
// Size: 2324 bytes

void FUN_8005758c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  char cVar10;
  float *pfVar7;
  undefined2 *puVar8;
  undefined4 *puVar9;
  int *piVar11;
  int *piVar12;
  undefined4 uVar13;
  undefined *puVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  undefined4 in_r10;
  int iVar20;
  double dVar21;
  undefined8 uVar22;
  undefined8 extraout_f1;
  double dVar23;
  undefined auStack_148 [12];
  float local_13c;
  float local_138;
  float local_134;
  float local_130;
  float local_12c;
  float local_128;
  undefined4 local_118;
  longlong local_38;
  undefined8 local_30;
  undefined4 local_28;
  float fStack_24;
  undefined4 local_20;
  float fStack_1c;
  
  if (DAT_803ddb38 == -1) {
    DAT_803ddb38 = -2;
    DAT_803dda60 = 8;
  }
  (**(code **)(*DAT_803dd6d4 + 4))();
  FUN_80069b0c();
  iVar16 = 0;
  piVar11 = &DAT_80382f14;
  piVar12 = &DAT_80382f00;
  do {
    iVar19 = *piVar11;
    iVar5 = *piVar12;
    iVar18 = 0;
    iVar20 = 0x10;
    do {
      puVar14 = (undefined *)(iVar19 + iVar18);
      *puVar14 = 0xff;
      *(undefined *)(iVar5 + 9) = 0xff;
      puVar14[1] = 0xff;
      *(undefined *)(iVar5 + 0x15) = 0xff;
      puVar14[2] = 0xff;
      *(undefined *)(iVar5 + 0x21) = 0xff;
      puVar14[3] = 0xff;
      *(undefined *)(iVar5 + 0x2d) = 0xff;
      puVar14[4] = 0xff;
      *(undefined *)(iVar5 + 0x39) = 0xff;
      puVar14[5] = 0xff;
      *(undefined *)(iVar5 + 0x45) = 0xff;
      puVar14[6] = 0xff;
      *(undefined *)(iVar5 + 0x51) = 0xff;
      puVar14[7] = 0xff;
      *(undefined *)(iVar5 + 0x5d) = 0xff;
      puVar14 = (undefined *)(iVar19 + iVar18 + 8);
      *puVar14 = 0xff;
      *(undefined *)(iVar5 + 0x69) = 0xff;
      puVar14[1] = 0xff;
      *(undefined *)(iVar5 + 0x75) = 0xff;
      puVar14[2] = 0xff;
      *(undefined *)(iVar5 + 0x81) = 0xff;
      puVar14[3] = 0xff;
      *(undefined *)(iVar5 + 0x8d) = 0xff;
      puVar14[4] = 0xff;
      *(undefined *)(iVar5 + 0x99) = 0xff;
      puVar14[5] = 0xff;
      *(undefined *)(iVar5 + 0xa5) = 0xff;
      puVar14[6] = 0xff;
      *(undefined *)(iVar5 + 0xb1) = 0xff;
      puVar14[7] = 0xff;
      *(undefined *)(iVar5 + 0xbd) = 0xff;
      iVar5 = iVar5 + 0xc0;
      iVar18 = iVar18 + 0x10;
      iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    piVar11 = piVar11 + 1;
    piVar12 = piVar12 + 1;
    iVar16 = iVar16 + 1;
  } while (iVar16 < 5);
  iVar16 = 0;
  iVar5 = 0;
  iVar20 = 8;
  do {
    *(undefined2 *)(DAT_803ddb14 + iVar16) = 0xffff;
    *(undefined4 *)(DAT_803ddb1c + iVar5) = 0;
    *(undefined2 *)(DAT_803ddb14 + iVar16 + 2) = 0xffff;
    *(undefined4 *)(DAT_803ddb1c + iVar5 + 4) = 0;
    *(undefined2 *)(DAT_803ddb14 + iVar16 + 4) = 0xffff;
    *(undefined4 *)(DAT_803ddb1c + iVar5 + 8) = 0;
    *(undefined2 *)(DAT_803ddb14 + iVar16 + 6) = 0xffff;
    *(undefined4 *)(DAT_803ddb1c + iVar5 + 0xc) = 0;
    *(undefined2 *)(DAT_803ddb14 + iVar16 + 8) = 0xffff;
    *(undefined4 *)(DAT_803ddb1c + iVar5 + 0x10) = 0;
    *(undefined2 *)(DAT_803ddb14 + iVar16 + 10) = 0xffff;
    *(undefined4 *)(DAT_803ddb1c + iVar5 + 0x14) = 0;
    *(undefined2 *)(DAT_803ddb14 + iVar16 + 0xc) = 0xffff;
    *(undefined4 *)(DAT_803ddb1c + iVar5 + 0x18) = 0;
    iVar17 = DAT_803ddb14;
    *(undefined2 *)(DAT_803ddb14 + iVar16 + 0xe) = 0xffff;
    iVar15 = DAT_803ddb1c;
    *(undefined4 *)(DAT_803ddb1c + iVar5 + 0x1c) = 0;
    iVar16 = iVar16 + 0x10;
    iVar5 = iVar5 + 0x20;
    iVar20 = iVar20 + -1;
  } while (iVar20 != 0);
  DAT_803ddb18 = 0;
  DAT_803dda6c = 0;
  cVar10 = (**(code **)(*DAT_803dd72c + 0x74))();
  pfVar7 = (float *)(**(code **)(*DAT_803dd72c + 0x90))();
  dVar21 = (double)FUN_802925a0();
  DAT_803dda50 = (int)dVar21;
  local_38 = (longlong)DAT_803dda50;
  dVar21 = (double)FUN_802925a0();
  DAT_803dda54 = (int)dVar21;
  local_30 = (double)(longlong)DAT_803dda54;
  DAT_803872a8 = *pfVar7;
  DAT_803872ac = pfVar7[1];
  DAT_803872b0 = pfVar7[2];
  DAT_803872b4 = 1;
  DAT_803dda48 = (float)(DAT_803dda50 * 0x280);
  DAT_803dda4c = (float)(DAT_803dda54 * 0x280);
  fStack_24 = -DAT_803dda48;
  local_28 = 0x43300000;
  FLOAT_803dda58 = (float)((double)CONCAT44(0x43300000,fStack_24) - DOUBLE_803df840);
  fStack_1c = -DAT_803dda4c;
  local_20 = 0x43300000;
  FLOAT_803dda5c = (float)((double)CONCAT44(0x43300000,fStack_1c) - DOUBLE_803df840);
  uVar13 = 0xffffffff;
  DAT_803ddb48 = 0xffffffff;
  DAT_803ddb44 = DAT_803ddb44 + -1;
  DAT_803ddb40 = 0xffffffff;
  DAT_803dda61 = *(undefined *)((int)pfVar7 + 0xd);
  DAT_803dda68 = DAT_803dda68 & 0x82008 | 0x489f4;
  DAT_803dda84 = 0;
  DAT_803dda74 = 0;
  DAT_803dda77 = 0;
  FLOAT_803dc28c = FLOAT_803df84c;
  DAT_803dda80 = 0xffffffff;
  FLOAT_803ddb4c = FLOAT_803dda5c;
  FLOAT_803ddb50 = FLOAT_803dda58;
  FUN_800e8a1c();
  fVar2 = pfVar7[2];
  dVar23 = (double)fVar2;
  fVar3 = pfVar7[1];
  dVar21 = (double)fVar3;
  if ((((DAT_803dda68 & 2) == 0) || ((DAT_803dda68 & 0x800) != 0)) &&
     (uVar6 = DAT_803dda68 | 2, uVar4 = DAT_803dda68 & 0x800, DAT_803dda68 = uVar6,
     FLOAT_803ddadc = fVar2, FLOAT_803ddae0 = fVar3, FLOAT_803ddae4 = *pfVar7, uVar4 != 0)) {
    dVar21 = (double)FUN_80058210(dVar21,dVar23,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  DAT_803dda68 = DAT_803dda68 & 0xfffffffb;
  uVar22 = FUN_80064e08(dVar21,dVar23,param_3,param_4,param_5,param_6,param_7,param_8);
  puVar8 = FUN_8000facc();
  *(float *)(puVar8 + 6) = *pfVar7;
  *(float *)(puVar8 + 8) = pfVar7[1];
  *(float *)(puVar8 + 10) = pfVar7[2];
  FUN_8002bb04(uVar22,dVar23,param_3,param_4,param_5,param_6,param_7,param_8);
  DAT_803ddb3d = 0;
  (**(code **)(*DAT_803dd718 + 0x1c))();
  (**(code **)(*DAT_803dd700 + 4))();
  (**(code **)(*DAT_803dd6fc + 4))();
  (**(code **)(*DAT_803dd6f8 + 4))();
  (**(code **)(*DAT_803dd708 + 4))();
  (**(code **)(*DAT_803dd6e4 + 0x14))();
  (**(code **)(*DAT_803dd6e4 + 8))();
  (**(code **)(*DAT_803dd6dc + 8))();
  (**(code **)(*DAT_803dd6d8 + 8))();
  uVar22 = (**(code **)(*DAT_803dd6e0 + 8))();
  uVar22 = FUN_8006fe48(extraout_f1,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,
                        (int)((ulonglong)uVar22 >> 0x20),(int)uVar22,uVar13,iVar15,iVar17,iVar18,
                        iVar19,in_r10);
  iVar16 = FUN_8002bac4();
  if (((DAT_803ddb38 == -2) && (iVar16 != 0)) && ((cVar10 == '\0' || (cVar10 == '\x01')))) {
    iVar5 = FUN_800e876c();
    if ((short)iVar5 != -1) {
      uVar22 = (**(code **)(*DAT_803dd6d0 + 0x24))(0,(int)(short)iVar5,1);
    }
    pfVar7 = (float *)FUN_800e877c();
    if (*(ushort *)(pfVar7 + 1) != 0xffff) {
      uVar22 = FUN_80008b74(uVar22,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,iVar16,
                            iVar16,(uint)*(ushort *)(pfVar7 + 1),0,iVar17,iVar18,iVar19,in_r10);
    }
    if (*(ushort *)((int)pfVar7 + 6) != 0xffff) {
      uVar22 = FUN_80008b74(uVar22,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,iVar16,
                            iVar16,(uint)*(ushort *)((int)pfVar7 + 6),0,iVar17,iVar18,iVar19,in_r10)
      ;
    }
    if (*(ushort *)((int)pfVar7 + 10) != 0xffff) {
      uVar22 = FUN_80008b74(uVar22,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,iVar16,
                            iVar16,(uint)*(ushort *)((int)pfVar7 + 10),0,iVar17,iVar18,iVar19,in_r10
                           );
    }
    if (*(ushort *)(pfVar7 + 3) != 0xffff) {
      FUN_80008b74(uVar22,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,iVar16,iVar16,
                   (uint)*(ushort *)(pfVar7 + 3),0,iVar17,iVar18,iVar19,in_r10);
    }
    FUN_80088f20(1,(*(byte *)(pfVar7 + 0x10) & 2) != 0);
    FUN_80088f20(2,(*(byte *)(pfVar7 + 0x10) & 4) != 0);
    FUN_800890e0((double)FLOAT_803df84c,(uint)((*(byte *)(pfVar7 + 0x10) & 0x10) != 0));
    bVar1 = *(byte *)(pfVar7 + 0x10);
    puVar9 = FUN_800e877c();
    if ((bVar1 & 1) == 0) {
      DAT_803dda68 = DAT_803dda68 & 0xffffffaf;
      *(byte *)(puVar9 + 0x10) = *(byte *)(puVar9 + 0x10) & 0xf6;
    }
    else {
      DAT_803dda68 = DAT_803dda68 | 0x50;
      *(byte *)(puVar9 + 0x10) = *(byte *)(puVar9 + 0x10) | 9;
    }
    bVar1 = *(byte *)(pfVar7 + 0x10);
    puVar9 = FUN_800e877c();
    if ((bVar1 & 8) == 0) {
      DAT_803dda68 = DAT_803dda68 & 0xffffffbf;
      *(byte *)(puVar9 + 0x10) = *(byte *)(puVar9 + 0x10) & 0xf7;
    }
    else {
      DAT_803dda68 = DAT_803dda68 | 0x40;
      *(byte *)(puVar9 + 0x10) = *(byte *)(puVar9 + 0x10) | 8;
    }
    if ((*(byte *)(pfVar7 + 0x10) & 0x20) == 0) {
      DAT_803dda80 = 0xffffffff;
    }
    else {
      DAT_803dda80 = 1;
    }
    local_118 = 0;
    local_13c = FLOAT_803df84c;
    local_138 = FLOAT_803df84c;
    local_134 = FLOAT_803df84c;
    local_130 = FLOAT_803df84c;
    local_12c = FLOAT_803df84c;
    local_128 = FLOAT_803df84c;
    if (*(ushort *)((int)pfVar7 + 0xe) != 0xffff) {
      fStack_1c = -pfVar7[5];
      local_20 = 0x43300000;
      local_13c = (float)((double)CONCAT44(0x43300000,fStack_1c) - DOUBLE_803df840);
      fStack_24 = -pfVar7[6];
      local_28 = 0x43300000;
      local_138 = (float)((double)CONCAT44(0x43300000,fStack_24) - DOUBLE_803df840);
      local_30 = (double)CONCAT44(0x43300000,-pfVar7[7]);
      local_134 = (float)(local_30 - DOUBLE_803df840);
      FUN_80008cbc(DOUBLE_803df840,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,
                   auStack_148,iVar16,(uint)*(ushort *)((int)pfVar7 + 0xe),0,iVar17,iVar18,iVar19,
                   in_r10);
    }
    if (*(ushort *)(pfVar7 + 4) != 0xffff) {
      fStack_1c = -pfVar7[8];
      local_20 = 0x43300000;
      local_13c = (float)((double)CONCAT44(0x43300000,fStack_1c) - DOUBLE_803df840);
      fStack_24 = -pfVar7[9];
      local_28 = 0x43300000;
      local_138 = (float)((double)CONCAT44(0x43300000,fStack_24) - DOUBLE_803df840);
      local_30 = (double)CONCAT44(0x43300000,-pfVar7[10]);
      local_134 = (float)(local_30 - DOUBLE_803df840);
      FUN_80008cbc(DOUBLE_803df840,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,
                   auStack_148,iVar16,(uint)*(ushort *)(pfVar7 + 4),0,iVar17,iVar18,iVar19,in_r10);
    }
    if (*(ushort *)((int)pfVar7 + 0x12) != 0xffff) {
      fStack_1c = -pfVar7[0xb];
      local_20 = 0x43300000;
      local_13c = (float)((double)CONCAT44(0x43300000,fStack_1c) - DOUBLE_803df840);
      fStack_24 = -pfVar7[0xc];
      local_28 = 0x43300000;
      local_138 = (float)((double)CONCAT44(0x43300000,fStack_24) - DOUBLE_803df840);
      local_30 = (double)CONCAT44(0x43300000,-pfVar7[0xd]);
      local_134 = (float)(local_30 - DOUBLE_803df840);
      FUN_80008cbc(DOUBLE_803df840,dVar23,param_3,param_4,param_5,param_6,param_7,param_8,
                   auStack_148,iVar16,(uint)*(ushort *)((int)pfVar7 + 0x12),0,iVar17,iVar18,iVar19,
                   in_r10);
    }
    (**(code **)(*DAT_803dd6d8 + 0x28))((double)*pfVar7);
  }
  else {
    (**(code **)(*DAT_803dd6d8 + 0x28))((double)FLOAT_803df850);
    (**(code **)(*DAT_803dd6e4 + 0x1c))(1);
  }
  FUN_800e8a10();
  FUN_80130110(0);
  FUN_80130118();
  return;
}

