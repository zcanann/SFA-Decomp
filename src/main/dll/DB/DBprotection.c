#include "ghidra_import.h"
#include "main/dll/DB/DBprotection.h"

extern undefined4 FUN_8000b598();
extern undefined4 FUN_8000b7dc();
extern undefined4 FUN_8000b844();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_800201ac();
extern uint FUN_80021884();
extern undefined4 FUN_80021fac();
extern uint FUN_80022264();
extern undefined4 FUN_80022790();
extern int FUN_8002e1f4();
extern undefined4 FUN_80035ff8();
extern uint FUN_801e2b60();
extern undefined4 FUN_801ef394();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e6458;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6360;
extern f32 FLOAT_803e6364;
extern f32 FLOAT_803e6368;
extern f32 FLOAT_803e636c;
extern f32 FLOAT_803e6370;
extern f32 FLOAT_803e6374;
extern f32 FLOAT_803e6378;
extern f32 FLOAT_803e6384;
extern f32 FLOAT_803e6388;
extern f32 FLOAT_803e638c;
extern f32 FLOAT_803e6390;
extern f32 FLOAT_803e6394;
extern f32 FLOAT_803e6398;
extern f32 FLOAT_803e639c;
extern f32 FLOAT_803e63a0;
extern f32 FLOAT_803e63a4;
extern f32 FLOAT_803e63a8;
extern f32 FLOAT_803e63ac;
extern f32 FLOAT_803e63b0;
extern f32 FLOAT_803e63b4;
extern f32 FLOAT_803e63b8;
extern f32 FLOAT_803e63bc;
extern f32 FLOAT_803e63c0;
extern f32 FLOAT_803e63c4;
extern f32 FLOAT_803e63c8;
extern f32 FLOAT_803e63cc;
extern f32 FLOAT_803e63d0;
extern f32 FLOAT_803e63d4;
extern f32 FLOAT_803e63d8;
extern f32 FLOAT_803e63dc;
extern f32 FLOAT_803e63e0;
extern f32 FLOAT_803e63e4;
extern f32 FLOAT_803e63e8;
extern f32 FLOAT_803e63ec;
extern f32 FLOAT_803e63f0;
extern f32 FLOAT_803e63f4;
extern f32 FLOAT_803e63f8;
extern f32 FLOAT_803e63fc;
extern f32 FLOAT_803e6400;
extern f32 FLOAT_803e6404;
extern f32 FLOAT_803e6408;
extern f32 FLOAT_803e640c;
extern f32 FLOAT_803e6410;
extern f32 FLOAT_803e6414;
extern f32 FLOAT_803e6418;
extern f32 FLOAT_803e641c;
extern f32 FLOAT_803e6420;
extern f32 FLOAT_803e6424;
extern f32 FLOAT_803e6428;
extern f32 FLOAT_803e642c;
extern f32 FLOAT_803e6430;
extern f32 FLOAT_803e6434;
extern f32 FLOAT_803e6438;
extern f32 FLOAT_803e643c;
extern f32 FLOAT_803e6440;
extern f32 FLOAT_803e6444;
extern f32 FLOAT_803e6448;
extern f32 FLOAT_803e644c;
extern f32 FLOAT_803e6450;

/*
 * --INFO--
 *
 * Function: FUN_801e0018
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801E0018
 * EN v1.1 Size: 5732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e0018(void)
{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  ushort *puVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  float fVar11;
  float *pfVar12;
  int iVar13;
  undefined unaff_r31;
  double dVar14;
  double dVar15;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double dVar17;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_148;
  int local_144;
  int local_140;
  ushort local_13c;
  ushort local_13a;
  ushort local_138;
  float local_134;
  float local_130;
  float local_12c;
  float local_128;
  float afStack_124 [17];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined4 local_c8;
  uint uStack_c4;
  undefined8 local_c0;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  puVar7 = (ushort *)FUN_80286840();
  iVar13 = *(int *)(puVar7 + 0x26);
  pfVar12 = *(float **)(puVar7 + 0x5c);
  local_148 = FLOAT_803e6360;
  *(undefined *)(puVar7 + 0x56) = 0xff;
  if ((pfVar12[0x12] != 0.0) && ((*(ushort *)((int)pfVar12[0x12] + 6) & 0x40) != 0)) {
    pfVar12[0x12] = 0.0;
  }
  if (pfVar12[0x12] == 0.0) {
    iVar8 = FUN_8002e1f4(&local_140,&local_144);
    for (; local_140 < local_144; local_140 = local_140 + 1) {
      fVar11 = *(float *)(iVar8 + local_140 * 4);
      if (*(short *)((int)fVar11 + 0x46) == 0x8c) {
        pfVar12[0x12] = fVar11;
        local_140 = local_144;
      }
    }
  }
  if (*(char *)((int)pfVar12 + 0x29) < '\x02') {
    FUN_8000b844((int)puVar7,0x143);
  }
  else {
    FUN_8000bb38((uint)puVar7,0x143);
  }
  fVar11 = pfVar12[0x12];
  if (fVar11 == 0.0) goto LAB_801e1614;
  if ((fVar11 != 0.0) && (*(int *)((int)fVar11 + 0xf4) == 0)) {
    FUN_801ef394((int)fVar11,pfVar12 + 0x14,pfVar12 + 0x15,pfVar12 + 0x16);
  }
  *(ushort *)((int)pfVar12 + 0x26) = *(short *)((int)pfVar12 + 0x26) - (ushort)DAT_803dc070;
  if (*(short *)((int)pfVar12 + 0x26) < 0) {
    *(undefined2 *)((int)pfVar12 + 0x26) = 0;
  }
  cVar1 = *(char *)((int)pfVar12 + 0x2b);
  if (cVar1 == '\a') {
    *(undefined *)((int)pfVar12 + 0x79) = 3;
  }
  else if (cVar1 == '\b') {
    *(undefined *)((int)pfVar12 + 0x79) = 4;
  }
  else if (cVar1 == '\t') {
    *(undefined *)((int)pfVar12 + 0x79) = 5;
  }
  fVar2 = FLOAT_803e636c;
  if (*(char *)((int)pfVar12 + 0x29) < '\x02') {
    pfVar12[0x24] = pfVar12[0x24] - FLOAT_803dc074;
    if (pfVar12[0x24] <= FLOAT_803e6364) {
      *(byte *)(pfVar12 + 0x28) = *(byte *)(pfVar12 + 0x28) ^ 1;
      uVar9 = FUN_80022264(0xb4,300);
      local_e0 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
      pfVar12[0x24] = (float)(local_e0 - DOUBLE_803e6458);
    }
    if (*(char *)(pfVar12 + 0x28) == '\0') {
      pfVar12[0x22] = pfVar12[0x22] - FLOAT_803dc074;
    }
    else {
      pfVar12[0x22] = FLOAT_803e6368 * FLOAT_803dc074 + pfVar12[0x22];
    }
    pfVar12[0x25] = pfVar12[0x25] - FLOAT_803dc074;
    if (pfVar12[0x25] <= FLOAT_803e6364) {
      *(byte *)((int)pfVar12 + 0xa1) = *(byte *)((int)pfVar12 + 0xa1) ^ 1;
      uVar9 = FUN_80022264(0xb4,300);
      local_e0 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
      pfVar12[0x25] = (float)(local_e0 - DOUBLE_803e6458);
    }
    if (*(char *)((int)pfVar12 + 0xa1) == '\0') {
      pfVar12[0x23] = pfVar12[0x23] - FLOAT_803dc074;
    }
    else {
      pfVar12[0x23] = FLOAT_803e6368 * FLOAT_803dc074 + pfVar12[0x23];
    }
  }
  else {
    pfVar12[0x22] = -(FLOAT_803e636c * FLOAT_803dc074 - pfVar12[0x22]);
    pfVar12[0x23] = -(fVar2 * FLOAT_803dc074 - pfVar12[0x23]);
  }
  fVar2 = pfVar12[0x22];
  fVar3 = FLOAT_803e6364;
  if ((FLOAT_803e6364 <= fVar2) && (fVar3 = fVar2, FLOAT_803e6370 < fVar2)) {
    fVar3 = FLOAT_803e6370;
  }
  pfVar12[0x22] = fVar3;
  fVar2 = pfVar12[0x23];
  fVar3 = FLOAT_803e6364;
  if ((FLOAT_803e6364 <= fVar2) && (fVar3 = fVar2, FLOAT_803e6370 < fVar2)) {
    fVar3 = FLOAT_803e6370;
  }
  pfVar12[0x23] = fVar3;
  cVar1 = *(char *)((int)pfVar12 + 0x29);
  if (cVar1 == '\x01') {
    puVar7[0x7a] = 0;
    puVar7[0x7b] = 2;
    local_148 = FLOAT_803e6360;
    (**(code **)(*DAT_803dd6d0 + 0x60))(&local_148,0);
    if (*(short *)((int)pfVar12 + 0x82) != 0) {
      *(short *)((int)pfVar12 + 0x82) = *(short *)((int)pfVar12 + 0x82) + -1;
    }
    cVar1 = *(char *)((int)pfVar12 + 0x7a);
    if (cVar1 == '\x03') {
      dVar16 = (double)(*(float *)((int)fVar11 + 0xc) - FLOAT_803e63b4);
      dVar15 = (double)(FLOAT_803e63b0 + *(float *)((int)fVar11 + 0x10));
      dVar14 = (double)(FLOAT_803e63b8 + pfVar12[0x16] +
                       (*(float *)((int)fVar11 + 0x14) - pfVar12[0xd]));
      *(undefined *)((int)pfVar12 + 0x7b) = 0;
    }
    else if (cVar1 < '\x03') {
      if (cVar1 == '\x01') {
        dVar16 = (double)(pfVar12[0x14] - FLOAT_803e63a8);
        dVar14 = (double)pfVar12[0x16];
        dVar15 = (double)(FLOAT_803e6384 + *(float *)((int)fVar11 + 0x10));
      }
      else if (cVar1 < '\x01') {
        if (cVar1 < '\0') goto LAB_801e0878;
        dVar16 = (double)(pfVar12[0x14] - FLOAT_803e63a4);
        dVar14 = (double)pfVar12[0x16];
        dVar15 = (double)(FLOAT_803e6384 + *(float *)((int)fVar11 + 0x10));
        if ((*(short *)((int)pfVar12 + 0x82) < 1) &&
           ((*(char *)(pfVar12 + 0x1f) == '\0' || (*(char *)(pfVar12 + 0x1f) == '\x05')))) {
          *(undefined2 *)((int)pfVar12 + 0x82) = 200;
        }
        FUN_8000b598((int)puVar7,2);
      }
      else {
        dVar16 = (double)(*(float *)((int)fVar11 + 0xc) - FLOAT_803e63ac);
        dVar14 = (double)pfVar12[0x16];
        dVar15 = (double)(FLOAT_803e63b0 + *(float *)((int)fVar11 + 0x10));
      }
    }
    else if (cVar1 == '\x05') {
      dVar16 = (double)(*(float *)((int)fVar11 + 0xc) - FLOAT_803e63b4);
      dVar15 = (double)(FLOAT_803e63b0 + *(float *)((int)fVar11 + 0x10));
      dVar14 = (double)((pfVar12[0x16] - FLOAT_803e63b8) +
                       (*(float *)((int)fVar11 + 0x14) - pfVar12[0xd]));
      *(undefined *)((int)pfVar12 + 0x7b) = 0;
    }
    else if (cVar1 < '\x05') {
      dVar16 = (double)(*(float *)((int)fVar11 + 0xc) - FLOAT_803e63b4);
      dVar14 = (double)(FLOAT_803e63bc + pfVar12[0x16]);
      dVar15 = (double)(FLOAT_803e63b0 + *(float *)((int)fVar11 + 0x10));
      *(undefined *)((int)pfVar12 + 0x7b) = 0;
    }
    else {
LAB_801e0878:
      *(undefined *)((int)pfVar12 + 0x7b) = 0;
      dVar16 = (double)(pfVar12[0x14] - FLOAT_803e63c0);
      dVar14 = (double)pfVar12[0x16];
      dVar15 = (double)(FLOAT_803e63c4 + *(float *)((int)fVar11 + 0x10));
    }
    dVar17 = (double)(float)(dVar16 - (double)*(float *)(puVar7 + 6));
    dVar16 = (double)(float)(dVar15 - (double)*(float *)(puVar7 + 8));
    dVar14 = (double)(float)(dVar14 - (double)*(float *)(puVar7 + 10));
    pfVar12[7] = FLOAT_803e638c;
    dVar15 = FUN_80293900((double)(float)(dVar14 * dVar14 +
                                         (double)(float)(dVar17 * dVar17 +
                                                        (double)(float)(dVar16 * dVar16))));
    fVar2 = (float)(dVar16 * (double)FLOAT_803e6390);
    fVar3 = (float)(dVar14 * (double)FLOAT_803e6390);
    fVar4 = (float)(dVar17 * (double)FLOAT_803e6394);
    if (FLOAT_803e63c8 < (float)(dVar17 * (double)FLOAT_803e6394)) {
      fVar4 = FLOAT_803e63c8;
    }
    if (fVar4 < FLOAT_803e63cc) {
      fVar4 = FLOAT_803e63cc;
    }
    if (FLOAT_803e63d0 < fVar2) {
      fVar2 = FLOAT_803e63d0;
    }
    if (fVar2 < FLOAT_803e63d4) {
      fVar2 = FLOAT_803e63d4;
    }
    if (FLOAT_803e63d8 < fVar3) {
      fVar3 = FLOAT_803e63d8;
    }
    if (fVar3 < FLOAT_803e63dc) {
      fVar3 = FLOAT_803e63dc;
    }
    *(ushort *)((int)pfVar12 + 0x6e) = *(short *)((int)pfVar12 + 0x6e) + (ushort)DAT_803dc070;
    *pfVar12 = (fVar4 - *pfVar12) * FLOAT_803e63e0 + *pfVar12;
    pfVar12[1] = pfVar12[1] + (fVar2 - pfVar12[1]) / FLOAT_803e63e4;
    pfVar12[2] = pfVar12[2] + (fVar3 - pfVar12[2]) / FLOAT_803e63e8;
    in_f28 = (double)FLOAT_803e63ec;
    in_f29 = (double)FLOAT_803e63f0;
    in_f27 = (double)FLOAT_803e6364;
    cVar1 = *(char *)((int)pfVar12 + 0x7a);
    if (cVar1 == '\x03') {
      if ((dVar15 < (double)FLOAT_803e63a0) || (0x78 < *(short *)((int)pfVar12 + 0x6e))) {
        *(undefined *)((int)pfVar12 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
      }
    }
    else if (cVar1 < '\x03') {
      if (cVar1 == '\x01') {
        if (dVar15 < (double)FLOAT_803e63a0) {
          *(undefined *)((int)pfVar12 + 0x7a) = 2;
          *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
        }
      }
      else if (cVar1 < '\x01') {
        if (cVar1 < '\0') goto LAB_801e0ac0;
        if (dVar15 < (double)FLOAT_803e63f4) {
          *(undefined *)((int)pfVar12 + 0x7a) = 1;
          *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
        }
      }
      else if ((0xf0 < *(short *)((int)pfVar12 + 0x6e)) || (dVar15 < (double)FLOAT_803e63a0)) {
        *(undefined *)((int)pfVar12 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
      }
    }
    else if (cVar1 == '\x05') {
      if ((dVar15 < (double)FLOAT_803e63a0) || (0x78 < *(short *)((int)pfVar12 + 0x6e))) {
        *(undefined *)((int)pfVar12 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
      }
    }
    else if (cVar1 < '\x05') {
      if ((dVar15 < (double)FLOAT_803e63a0) || (0x78 < *(short *)((int)pfVar12 + 0x6e))) {
        *(undefined *)((int)pfVar12 + 0x7a) = 5;
        *(undefined2 *)((int)pfVar12 + 0x6e) = 3;
      }
    }
    else {
LAB_801e0ac0:
      if (dVar15 < (double)FLOAT_803e63f8) {
        if (*(char *)((int)pfVar12 + 0x2b) == '\x02') {
          *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
          *(undefined *)((int)pfVar12 + 0x29) = 0;
          *(undefined *)((int)pfVar12 + 0x2b) = 3;
        }
        else if (*(char *)((int)pfVar12 + 0x2b) == '\x05') {
          *(undefined *)((int)pfVar12 + 0x29) = 2;
          *(undefined *)((int)pfVar12 + 0x2b) = 6;
        }
      }
    }
    *(undefined2 *)((int)pfVar12 + 0x26) = 300;
    if ((*(char *)(pfVar12 + 0x1f) < '\x04') || ('\x02' < *(char *)((int)pfVar12 + 0x2b))) {
      if ('\x03' < *(char *)(pfVar12 + 0x1f)) {
        *(undefined *)((int)pfVar12 + 0x29) = 2;
        *(undefined *)(pfVar12 + 10) = 3;
        *(undefined *)((int)pfVar12 + 0x2b) = 6;
        *(undefined2 *)((int)pfVar12 + 0x82) = 200;
        pfVar12[3] = *(float *)((int)fVar11 + 0x14);
      }
    }
    else {
      *(undefined *)((int)pfVar12 + 0x29) = 0;
      *(undefined *)(pfVar12 + 10) = 1;
      *(undefined *)((int)pfVar12 + 0x2b) = 3;
      *(undefined *)(pfVar12 + 0x1f) = 5;
      *(undefined2 *)((int)pfVar12 + 0x82) = 200;
      uVar9 = FUN_801e2b60();
      FUN_8000b844(uVar9,0x2c6);
      FUN_8000bb38(uVar9,0x146);
      FUN_800201ac(0xf1e,0);
    }
  }
  else if (cVar1 < '\x01') {
    if (cVar1 < '\0') {
LAB_801e1380:
      puVar7[0x7a] = 0;
      puVar7[0x7b] = 7;
    }
    else {
      local_148 = FLOAT_803e6360;
      FUN_8000b7dc((int)puVar7,1);
      (**(code **)(*DAT_803dd6d0 + 0x60))(&local_148,0);
      puVar7[0x7a] = 0;
      puVar7[0x7b] = 1;
      dVar16 = (double)(pfVar12[0x14] - FLOAT_803e6374);
      local_e0 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar12 + 8) ^ 0x80000000);
      dVar15 = (double)FUN_80294964();
      dVar17 = (double)(float)((double)FLOAT_803e6378 * dVar15 + (double)pfVar12[0x16]);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar12 + 8) ^ 0x80000000);
      dVar15 = (double)FUN_802945e0();
      dVar14 = (double)FLOAT_803e6388;
      fVar5 = pfVar12[0x15] - FLOAT_803e6384;
      *(ushort *)(pfVar12 + 8) = *(short *)(pfVar12 + 8) + (ushort)DAT_803dc070 * 0xb6;
      fVar2 = *(float *)(puVar7 + 6);
      fVar3 = *(float *)(puVar7 + 8);
      fVar4 = *(float *)(puVar7 + 10);
      pfVar12[7] = FLOAT_803e638c;
      fVar6 = (float)(dVar16 - (double)fVar2) * FLOAT_803e6390;
      fVar3 = ((float)(dVar14 * dVar15 + (double)fVar5) - fVar3) * FLOAT_803e6390;
      fVar4 = (float)(dVar17 - (double)fVar4) * FLOAT_803e6390;
      fVar2 = pfVar12[7];
      if (fVar2 < fVar6) {
        fVar6 = fVar2;
      }
      fVar5 = -fVar2;
      if (fVar6 < fVar5) {
        fVar6 = fVar5;
      }
      if (fVar2 < fVar3) {
        fVar3 = fVar2;
      }
      if (fVar3 < fVar5) {
        fVar3 = fVar5;
      }
      if (fVar2 < fVar4) {
        fVar4 = fVar2;
      }
      if (fVar4 < fVar5) {
        fVar4 = fVar5;
      }
      iVar13 = (int)*(short *)((int)pfVar12 + 0x6e);
      fVar2 = FLOAT_803e6364;
      if ((0x77 < iVar13) && (fVar2 = fVar3, iVar13 < 0xb4)) {
        local_d8 = (double)CONCAT44(0x43300000,iVar13 - 0x78U ^ 0x80000000);
        fVar2 = fVar3 * ((float)(local_d8 - DOUBLE_803e6458) / FLOAT_803e6388);
      }
      *(ushort *)((int)pfVar12 + 0x6e) = *(short *)((int)pfVar12 + 0x6e) + (ushort)DAT_803dc070;
      fVar3 = FLOAT_803e6394;
      *pfVar12 = (fVar6 - *pfVar12) * FLOAT_803e6394 + *pfVar12;
      pfVar12[1] = (fVar2 - pfVar12[1]) * fVar3 + pfVar12[1];
      pfVar12[2] = (fVar4 - pfVar12[2]) * fVar3 + pfVar12[2];
      in_f28 = (double)FLOAT_803e6398;
      in_f29 = (double)FLOAT_803e639c;
      in_f27 = (double)FLOAT_803e63a0;
      if (*(char *)(pfVar12 + 10) == '\0') {
        if ((*(char *)((int)pfVar12 + 0x2b) < '\x02') && (-1 < *(char *)((int)pfVar12 + 0x2b))) {
          if ((*(short *)((int)pfVar12 + 0x82) != 0) &&
             (*(short *)((int)pfVar12 + 0x82) = *(short *)((int)pfVar12 + 0x82) + -1,
             *(short *)((int)pfVar12 + 0x82) < 1)) {
            *(undefined2 *)((int)pfVar12 + 0x82) = 200;
          }
        }
        else {
          *(undefined *)((int)pfVar12 + 0x2b) = 2;
          *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
          *(undefined *)((int)pfVar12 + 0x29) = 1;
          *(undefined *)(pfVar12 + 10) = 1;
          *(undefined *)(pfVar12 + 0x1f) = 0;
          *(undefined *)((int)pfVar12 + 0x7a) = 0;
          *(undefined2 *)((int)pfVar12 + 0x82) = 200;
          FUN_800201ac(0xf1e,1);
        }
      }
      else if ((*(char *)((int)pfVar12 + 0x2b) < '\x05') &&
              ('\x02' < *(char *)((int)pfVar12 + 0x2b))) {
        if ((*(short *)((int)pfVar12 + 0x82) != 0) &&
           (*(short *)((int)pfVar12 + 0x82) = *(short *)((int)pfVar12 + 0x82) + -1,
           *(short *)((int)pfVar12 + 0x82) < 1)) {
          *(undefined2 *)((int)pfVar12 + 0x82) = 200;
        }
      }
      else {
        *(undefined *)((int)pfVar12 + 0x2b) = 5;
        *(undefined2 *)((int)pfVar12 + 0x6e) = 0;
        *(undefined *)((int)pfVar12 + 0x29) = 1;
        *(undefined *)(pfVar12 + 10) = 2;
        *(undefined *)((int)pfVar12 + 0x7a) = 0;
        *(undefined2 *)((int)pfVar12 + 0x82) = 200;
      }
    }
  }
  else {
    if ('\b' < cVar1) goto LAB_801e1380;
    local_148 = FLOAT_803e6360;
    FUN_8000b7dc((int)puVar7,2);
    (**(code **)(*DAT_803dd6d0 + 0x60))(&local_148,0);
    puVar7[0x7a] = 0;
    puVar7[0x7b] = 3;
    if (*(short *)((int)pfVar12 + 0x82) != 0) {
      *(short *)((int)pfVar12 + 0x82) = *(short *)((int)pfVar12 + 0x82) + -1;
    }
    switch(*(undefined *)((int)pfVar12 + 0x29)) {
    case 2:
      in_f25 = (double)FLOAT_803e63fc;
      in_f29 = (double)(pfVar12[0x14] - FLOAT_803e6400);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar12 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e6404 * (float)(local_d8 - DOUBLE_803e6458) - pfVar12[0x16]);
      in_f30 = (double)pfVar12[0x15];
      in_f26 = (double)FLOAT_803e6408;
      unaff_r31 = 3;
      break;
    case 3:
      in_f25 = (double)FLOAT_803e640c;
      in_f29 = (double)(pfVar12[0x14] - FLOAT_803e6410);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar12 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e6408 * (float)(local_d8 - DOUBLE_803e6458) - pfVar12[0x16]);
      in_f30 = (double)(FLOAT_803e63bc + pfVar12[0x15]);
      unaff_r31 = 4;
      in_f26 = (double)FLOAT_803e6414;
      break;
    case 4:
      in_f25 = (double)FLOAT_803e640c;
      in_f29 = (double)(pfVar12[0x14] - FLOAT_803e6400);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar12 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e63a0 * (float)(local_d8 - DOUBLE_803e6458) - pfVar12[0x16]);
      in_f30 = (double)(FLOAT_803e63bc + pfVar12[0x15]);
      unaff_r31 = 5;
      in_f26 = (double)FLOAT_803e6414;
      break;
    case 5:
      in_f25 = (double)FLOAT_803e63a0;
      puVar7[0x7a] = 0;
      puVar7[0x7b] = 4;
      in_f29 = (double)(pfVar12[0x14] - FLOAT_803e6418);
      in_f31 = (double)pfVar12[0x16];
      in_f30 = (double)(pfVar12[0x15] - FLOAT_803e63bc);
      unaff_r31 = 6;
      in_f26 = (double)FLOAT_803e6414;
      if ((*(short *)((int)pfVar12 + 0x82) < 1) && (*(char *)((int)pfVar12 + 0x2b) == '\x06')) {
        *(undefined2 *)((int)pfVar12 + 0x82) = 200;
      }
      break;
    case 6:
      in_f25 = (double)FLOAT_803e6368;
      in_f29 = (double)(FLOAT_803e641c + pfVar12[0x14]);
      local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar12 + 0x2a) ^ 0x80000000);
      in_f31 = -(double)(FLOAT_803e6404 * (float)(local_d8 - DOUBLE_803e6458) - pfVar12[0x16]);
      in_f30 = (double)(FLOAT_803e63b0 + pfVar12[0x15]);
      unaff_r31 = 7;
      in_f26 = (double)FLOAT_803e63bc;
      break;
    case 7:
      in_f25 = (double)FLOAT_803e6368;
      in_f29 = (double)(FLOAT_803e6420 + pfVar12[0x14]);
      in_f31 = (double)pfVar12[0x16];
      in_f30 = (double)(FLOAT_803e6424 + *(float *)((int)fVar11 + 0x10));
      unaff_r31 = 8;
      in_f26 = (double)FLOAT_803e63bc;
      break;
    case 8:
      in_f25 = (double)FLOAT_803e6428;
      in_f29 = (double)(pfVar12[0x14] - FLOAT_803e642c);
      in_f31 = (double)pfVar12[0x16];
      in_f30 = (double)(FLOAT_803e63bc + *(float *)((int)fVar11 + 0x10));
      unaff_r31 = 2;
      in_f26 = (double)FLOAT_803e641c;
    }
    pfVar12[7] = (float)((double)pfVar12[7] +
                        (double)((float)(in_f25 - (double)pfVar12[7]) / FLOAT_803e6430));
    dVar15 = FUN_80293900((double)((float)(in_f29 - (double)pfVar12[0xb]) *
                                   (float)(in_f29 - (double)pfVar12[0xb]) +
                                  (float)(in_f31 - (double)pfVar12[0xd]) *
                                  (float)(in_f31 - (double)pfVar12[0xd])));
    if ((*(char *)((int)pfVar12 + 0x29) == '\x05') && (dVar15 < (double)FLOAT_803e6434)) {
      puVar7[0x7a] = 0;
      puVar7[0x7b] = 5;
    }
    if (dVar15 < in_f26) {
      if (*(char *)((int)pfVar12 + 0x29) == '\x05') {
        *(char *)((int)pfVar12 + 0x2a) = -*(char *)((int)pfVar12 + 0x2a);
      }
      *(undefined *)((int)pfVar12 + 0x29) = unaff_r31;
    }
    uVar9 = FUN_80021884();
    uVar10 = FUN_80021884();
    iVar8 = ((uVar9 & 0xffff) + 0x8000) - (uint)*puVar7;
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    *(short *)(pfVar12 + 9) =
         *(short *)(pfVar12 + 9) +
         (short)((int)((uint)DAT_803dc070 * (iVar8 - *(short *)(pfVar12 + 9))) >> 4);
    cVar1 = *(char *)((int)pfVar12 + 0x29);
    if ((cVar1 == '\x03') || (cVar1 == '\x04')) {
      iVar8 = (int)((int)*(short *)(pfVar12 + 9) * (uint)DAT_803dc070) / 0x3c +
              ((int)((int)*(short *)(pfVar12 + 9) * (uint)DAT_803dc070) >> 0x1f);
      *puVar7 = *puVar7 + ((short)iVar8 - (short)(iVar8 >> 0x1f));
    }
    else if ((cVar1 == '\x06') || (cVar1 == '\x02')) {
      iVar8 = (int)((int)*(short *)(pfVar12 + 9) * (uint)DAT_803dc070) / 0x78 +
              ((int)((int)*(short *)(pfVar12 + 9) * (uint)DAT_803dc070) >> 0x1f);
      *puVar7 = *puVar7 + ((short)iVar8 - (short)(iVar8 >> 0x1f));
    }
    else {
      iVar8 = (int)((int)*(short *)(pfVar12 + 9) * (uint)DAT_803dc070) / 0x3c +
              ((int)((int)*(short *)(pfVar12 + 9) * (uint)DAT_803dc070) >> 0x1f);
      *puVar7 = *puVar7 + ((short)iVar8 - (short)(iVar8 >> 0x1f));
    }
    iVar8 = (uVar10 & 0xffff) - (uint)puVar7[1];
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    puVar7[1] = puVar7[1] + (short)((int)(iVar8 * (uint)DAT_803dc070) >> 6);
    FUN_80293900((double)((pfVar12[0x14] - *(float *)(puVar7 + 6)) *
                          (pfVar12[0x14] - *(float *)(puVar7 + 6)) +
                         (pfVar12[0x16] - *(float *)(puVar7 + 10)) *
                         (pfVar12[0x16] - *(float *)(puVar7 + 10))));
    local_d8 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar12 + 9) ^ 0x80000000);
    iVar8 = (int)(FLOAT_803e6438 * (float)(local_d8 - DOUBLE_803e6458));
    local_e0 = (double)(longlong)iVar8;
    uVar9 = iVar8 - (short)puVar7[2] >> 3;
    if (0x3c < (int)uVar9) {
      uVar9 = 0x3c;
    }
    if ((int)uVar9 < -0x3c) {
      uVar9 = 0xffffffc4;
    }
    local_d0 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
    uStack_c4 = (int)(short)puVar7[2] ^ 0x80000000;
    local_c8 = 0x43300000;
    iVar8 = (int)((float)(local_d0 - DOUBLE_803e6458) * FLOAT_803dc074 +
                 (float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e6458));
    local_c0 = (double)(longlong)iVar8;
    puVar7[2] = (ushort)iVar8;
    local_130 = FLOAT_803e6364;
    local_12c = FLOAT_803e6364;
    local_128 = FLOAT_803e6364;
    local_134 = FLOAT_803e643c;
    local_13c = *puVar7;
    local_13a = puVar7[1];
    local_138 = puVar7[2];
    FUN_80021fac(afStack_124,&local_13c);
    FUN_80022790((double)FLOAT_803e6364,(double)FLOAT_803e6364,
                 (double)(-pfVar12[7] * FLOAT_803dc074),afStack_124,pfVar12,pfVar12 + 1,pfVar12 + 2)
    ;
    if (*(char *)((int)pfVar12 + 0x29) == '\a') {
      pfVar12[0xb] = (float)in_f29;
      pfVar12[0xc] = (float)in_f30;
      pfVar12[0xd] = (float)in_f31;
      fVar2 = FLOAT_803e6364;
      pfVar12[0xe] = FLOAT_803e6364;
      pfVar12[0xf] = fVar2;
      pfVar12[0x10] = fVar2;
    }
    else {
      pfVar12[0xb] = pfVar12[0xb] + *pfVar12;
      pfVar12[0xc] = pfVar12[0xc] + pfVar12[1];
      pfVar12[0xd] = pfVar12[0xd] + pfVar12[2];
    }
    in_f29 = (double)FLOAT_803e6440;
    *(float *)(puVar7 + 6) = pfVar12[0xb] + pfVar12[0xe];
    *(float *)(puVar7 + 8) = pfVar12[0xc] + pfVar12[0xf];
    *(float *)(puVar7 + 10) =
         pfVar12[0xd] + pfVar12[0x10] + (*(float *)((int)fVar11 + 0x14) - pfVar12[3]);
    if ('\x06' < *(char *)((int)pfVar12 + 0x2b)) {
      if (*(short *)(pfVar12 + 0x1b) == 0) {
        FUN_80035ff8((int)puVar7);
        (**(code **)(*DAT_803dd6cc + 8))(0x41,1);
      }
      *(ushort *)(pfVar12 + 0x1b) = *(short *)(pfVar12 + 0x1b) + (ushort)DAT_803dc070;
      if (0x41 < *(short *)(pfVar12 + 0x1b)) {
        *puVar7 = 0;
        *(undefined *)((int)pfVar12 + 0x29) = 6;
        (**(code **)(*DAT_803dd6e4 + 0x20))(0);
        (**(code **)(*DAT_803dd6e4 + 0x24))(0);
        (**(code **)(*DAT_803dd6e4 + 0x28))((double)FLOAT_803e6364,(double)FLOAT_803e63f8);
        if (*(char *)(pfVar12 + 0x20) == '\0') {
          *(undefined *)(pfVar12 + 0x20) = 1;
        }
        *(undefined *)(pfVar12 + 0x1c) = 1;
        *(undefined4 *)(puVar7 + 6) = *(undefined4 *)(iVar13 + 8);
        *(float *)(puVar7 + 8) = FLOAT_803e6444;
        *(undefined4 *)(puVar7 + 10) = *(undefined4 *)(iVar13 + 0x10);
        FUN_8000b7dc((int)puVar7,1);
        (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(puVar7 + 0x1a),2,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,puVar7,0xffffffff);
        goto LAB_801e1614;
      }
    }
  }
  if (*(char *)((int)pfVar12 + 0x29) < '\x02') {
    pfVar12[0xb] = pfVar12[0x11] * *pfVar12 * FLOAT_803dc074 + pfVar12[0xb];
    pfVar12[0xc] = pfVar12[0x11] * pfVar12[1] * FLOAT_803dc074 + pfVar12[0xc];
    pfVar12[0xd] = pfVar12[0x11] * pfVar12[2] * FLOAT_803dc074 + pfVar12[0xd];
    pfVar12[0x11] = pfVar12[0x11] + FLOAT_803e6448;
    if (FLOAT_803e643c < pfVar12[0x11]) {
      pfVar12[0x11] = FLOAT_803e643c;
    }
    dVar15 = (double)FLOAT_803e644c;
    pfVar12[0x17] =
         (float)(dVar15 * (double)(FLOAT_803dc074 * (float)(in_f28 - (double)pfVar12[0x17])) +
                (double)pfVar12[0x17]);
    pfVar12[0x18] =
         (float)(dVar15 * (double)(FLOAT_803dc074 * (float)(in_f27 - (double)pfVar12[0x18])) +
                (double)pfVar12[0x18]);
    pfVar12[0x19] =
         (float)(dVar15 * (double)(FLOAT_803dc074 * (float)(in_f29 - (double)pfVar12[0x19])) +
                (double)pfVar12[0x19]);
    if (*(char *)((int)pfVar12 + 0x29) == '\0') {
      local_c0 = (double)CONCAT44(0x43300000,(int)*(short *)((int)fVar11 + 2) ^ 0x80000000);
      dVar15 = local_c0 - DOUBLE_803e6458;
      uStack_c4 = -(int)*(short *)((int)fVar11 + 4) ^ 0x80000000;
      local_c8 = 0x43300000;
      pfVar12[0x10] =
           FLOAT_803dc074 *
           pfVar12[0x19] *
           ((float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e6458) / pfVar12[0x17] -
           pfVar12[0x10]) + pfVar12[0x10];
      pfVar12[0xf] = FLOAT_803dc074 * pfVar12[0x19] * ((float)dVar15 / pfVar12[0x17] - pfVar12[0xf])
                     + pfVar12[0xf];
      fVar11 = FLOAT_803e6364;
      pfVar12[0xe] = FLOAT_803e6364;
      pfVar12[0xf] = fVar11;
      iVar13 = (int)(-pfVar12[0x10] * pfVar12[0x18]);
      local_d0 = (double)(longlong)iVar13;
      iVar13 = (int)(short)iVar13;
      iVar8 = (int)(FLOAT_803e6450 * -pfVar12[0xf] * pfVar12[0x18]);
      local_d8 = (double)(longlong)iVar8;
      iVar8 = (int)(short)iVar8;
    }
    else {
      pfVar12[0x10] = -(FLOAT_803dc074 * pfVar12[0x10] * pfVar12[0x19] - pfVar12[0x10]);
      pfVar12[0xf] = -(FLOAT_803dc074 * pfVar12[0xf] * pfVar12[0x19] - pfVar12[0xf]);
      iVar13 = 0;
      iVar8 = 0;
    }
    *(float *)(puVar7 + 6) = pfVar12[0xe] * pfVar12[0x11] + pfVar12[0xb];
    *(float *)(puVar7 + 8) = pfVar12[0xf] * pfVar12[0x11] + pfVar12[0xc];
    *(float *)(puVar7 + 10) = pfVar12[0x10] * pfVar12[0x11] + pfVar12[0xd];
    *(short *)((int)pfVar12 + 0x22) =
         *(short *)((int)pfVar12 + 0x22) +
         (short)((int)((uint)DAT_803dc070 * (iVar13 - *(short *)((int)pfVar12 + 0x22))) >> 5);
    puVar7[1] = puVar7[1] + (short)((int)((uint)DAT_803dc070 * (iVar8 - (short)puVar7[1])) >> 5);
    *puVar7 = *(short *)((int)pfVar12 + 0x22) + 0x4000;
    puVar7[2] = *puVar7 + 0xc000;
  }
LAB_801e1614:
  FUN_8028688c();
  return;
}
