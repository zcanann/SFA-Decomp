// Function: FUN_800648c0
// Entry: 800648c0
// Size: 1352 bytes

/* WARNING: Removing unreachable block (ram,0x80064de8) */
/* WARNING: Removing unreachable block (ram,0x800648d4) */

void FUN_800648c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  ushort uVar9;
  short *psVar10;
  ushort uVar11;
  int iVar12;
  undefined2 uVar13;
  short *psVar14;
  double extraout_f1;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps31_1;
  short asStack_1ad8 [3400];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float fStack_8;
  float fStack_4;
  
  fStack_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_80286834();
  DAT_803ddbce = 1;
  DAT_803ddbde = 0;
  DAT_803ddbdc = 0;
  bVar1 = *(byte *)(iVar2 + 0x5c);
  psVar14 = *(short **)(iVar2 + 0x30);
  dVar15 = extraout_f1;
  for (iVar12 = 0; iVar12 < (int)(uint)bVar1; iVar12 = iVar12 + 1) {
    if (DAT_803ddbde < 0x5dc) {
      puVar4 = (undefined *)(DAT_803ddbb4 + DAT_803ddbde * 0x10);
      *puVar4 = *(undefined *)(psVar14 + 6);
      puVar4[1] = *(undefined *)((int)psVar14 + 0xd);
      puVar4[3] = *(undefined *)((int)psVar14 + 0xf);
      if ((puVar4[3] & 0x3f) == 0x11) {
        puVar4[3] = puVar4[3] & 0xc0;
        puVar4[3] = puVar4[3] | 2;
      }
      puVar4[2] = *(undefined *)(psVar14 + 7);
      puVar4[2] = puVar4[2] ^ 0x10;
      *(short *)(puVar4 + 0xc) = psVar14[8];
      iVar5 = 0;
      psVar10 = psVar14;
      dVar16 = DOUBLE_803df958;
      do {
        uStack_44 = (int)*psVar10 ^ 0x80000000;
        local_48 = 0x43300000;
        dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar16);
        uStack_3c = (int)psVar10[2] ^ 0x80000000;
        local_40 = 0x43300000;
        param_2 = (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - dVar16);
        uStack_34 = (int)psVar10[4] ^ 0x80000000;
        local_38 = 0x43300000;
        param_3 = (double)(float)((double)CONCAT44(0x43300000,uStack_34) - dVar16);
        if (DAT_803ddbdc < 0x6a4) {
          iVar3 = FUN_8006416c(dVar15,param_2,param_3,DAT_803ddbde,(int)asStack_1ad8);
          *(short *)(puVar4 + 4) = (short)iVar3;
        }
        psVar10 = psVar10 + 1;
        puVar4 = puVar4 + 2;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 2);
      DAT_803ddbde = DAT_803ddbde + 1;
    }
    psVar14 = psVar14 + 10;
  }
  iVar12 = 0;
  for (iVar5 = 0; iVar5 < DAT_803ddbde; iVar5 = iVar5 + 1) {
    iVar3 = DAT_803ddbb4 + iVar12;
    sVar8 = asStack_1ad8[*(short *)(iVar3 + 4) * 2];
    if ((sVar8 < 0) || (sVar8 == iVar5)) {
      sVar8 = asStack_1ad8[*(short *)(iVar3 + 4) * 2 + 1];
      if ((sVar8 < 0) || (sVar8 == iVar5)) {
        *(undefined2 *)(iVar3 + 8) = 0xffff;
      }
      else {
        *(short *)(iVar3 + 8) = sVar8;
      }
    }
    else {
      *(short *)(iVar3 + 8) = sVar8;
    }
    sVar8 = asStack_1ad8[*(short *)(iVar3 + 6) * 2];
    if ((sVar8 < 0) || (sVar8 == iVar5)) {
      sVar8 = asStack_1ad8[*(short *)(iVar3 + 6) * 2 + 1];
      if ((sVar8 < 0) || (sVar8 == iVar5)) {
        *(undefined2 *)(iVar3 + 10) = 0xffff;
      }
      else {
        *(short *)(iVar3 + 10) = sVar8;
      }
    }
    else {
      *(short *)(iVar3 + 10) = sVar8;
    }
    iVar12 = iVar12 + 0x10;
  }
  iVar12 = DAT_803ddbde * 0x10 + DAT_803ddbdc * 0xc + 0x28;
  if (iVar12 != 0) {
    iVar12 = FUN_80023d8c(iVar12,-0xff01);
    *(int *)(iVar2 + 0x34) = iVar12;
    *(int *)(iVar2 + 0x3c) = *(int *)(iVar2 + 0x34) + DAT_803ddbde * 0x10;
    *(int *)(iVar2 + 0x38) = *(int *)(iVar2 + 0x3c) + DAT_803ddbdc * 0xc;
    iVar12 = 0;
    iVar5 = 5;
    do {
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 1) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 2) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 3) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 4) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 5) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 6) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 7) = 0xff;
      iVar12 = iVar12 + 8;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    uVar11 = 0xffff;
    iVar5 = 0;
    for (iVar12 = 0; iVar3 = (int)DAT_803ddbde, iVar12 < iVar3; iVar12 = iVar12 + 1) {
      sVar8 = 0;
      iVar7 = 0;
      iVar6 = DAT_803ddbb4;
      if (0 < iVar3) {
        do {
          if ((*(byte *)(iVar6 + 3) & 0x3f) < (*(byte *)(DAT_803ddbb4 + sVar8 * 0x10 + 3) & 0x3f)) {
            sVar8 = (short)iVar7;
          }
          iVar6 = iVar6 + 0x10;
          iVar7 = iVar7 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      iVar3 = sVar8 * 0x10;
      uVar9 = (short)*(char *)(DAT_803ddbb4 + iVar3 + 3) & 0x3f;
      if (0x13 < uVar9) {
        uVar9 = 1;
        FUN_80137c30(dVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_trackIntersect__FUNC_OVERFLOW__d_8030f43c,1,iVar6,DAT_803ddbb4,iVar7,in_r8,
                     in_r9,in_r10);
      }
      iVar6 = (int)(short)uVar11;
      if ((short)uVar9 != iVar6) {
        *(char *)(*(int *)(iVar2 + 0x38) + (short)uVar9 * 2) = (char)iVar12;
        uVar11 = uVar9;
        if (iVar6 != -1) {
          *(char *)(*(int *)(iVar2 + 0x38) + iVar6 * 2 + 1) = (char)iVar12;
        }
      }
      iVar7 = 0;
      uVar13 = (undefined2)iVar12;
      iVar6 = iVar12;
      if (0 < iVar12) {
        do {
          if (sVar8 == *(short *)(*(int *)(iVar2 + 0x34) + iVar7 + 8)) {
            *(undefined2 *)(*(int *)(iVar2 + 0x34) + iVar7 + 8) = uVar13;
          }
          if (sVar8 == *(short *)(*(int *)(iVar2 + 0x34) + iVar7 + 10)) {
            *(undefined2 *)(*(int *)(iVar2 + 0x34) + iVar7 + 10) = uVar13;
          }
          iVar7 = iVar7 + 0x10;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      iVar6 = 0;
      for (in_r8 = 0; in_r8 < DAT_803ddbde; in_r8 = in_r8 + 1) {
        iVar7 = DAT_803ddbb4 + iVar6;
        if (*(char *)(iVar7 + 3) != '\x14') {
          if (sVar8 == *(short *)(iVar7 + 8)) {
            *(undefined2 *)(iVar7 + 8) = uVar13;
          }
          if (sVar8 == *(short *)(DAT_803ddbb4 + iVar6 + 10)) {
            *(undefined2 *)(DAT_803ddbb4 + iVar6 + 10) = uVar13;
          }
        }
        iVar6 = iVar6 + 0x10;
      }
      dVar15 = (double)FUN_80003494(*(int *)(iVar2 + 0x34) + iVar5,DAT_803ddbb4 + iVar3,0x10);
      *(undefined *)(DAT_803ddbb4 + iVar3 + 3) = 0x14;
      iVar5 = iVar5 + 0x10;
    }
    if ((short)uVar11 != -1) {
      *(char *)(*(int *)(iVar2 + 0x38) + (short)uVar11 * 2 + 1) = (char)DAT_803ddbde;
    }
    FUN_80003494(*(uint *)(iVar2 + 0x3c),DAT_803ddbb8,DAT_803ddbdc * 0xc);
    DAT_803ddbde = 0;
    DAT_803ddbdc = 0;
  }
  FUN_80286880();
  return;
}

