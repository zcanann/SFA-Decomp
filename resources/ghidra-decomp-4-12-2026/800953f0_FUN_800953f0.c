// Function: FUN_800953f0
// Entry: 800953f0
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x80095668) */
/* WARNING: Removing unreachable block (ram,0x80095660) */
/* WARNING: Removing unreachable block (ram,0x80095658) */
/* WARNING: Removing unreachable block (ram,0x80095650) */
/* WARNING: Removing unreachable block (ram,0x80095648) */
/* WARNING: Removing unreachable block (ram,0x80095640) */
/* WARNING: Removing unreachable block (ram,0x80095638) */
/* WARNING: Removing unreachable block (ram,0x80095630) */
/* WARNING: Removing unreachable block (ram,0x80095628) */
/* WARNING: Removing unreachable block (ram,0x80095620) */
/* WARNING: Removing unreachable block (ram,0x80095618) */
/* WARNING: Removing unreachable block (ram,0x80095610) */
/* WARNING: Removing unreachable block (ram,0x80095458) */
/* WARNING: Removing unreachable block (ram,0x80095450) */
/* WARNING: Removing unreachable block (ram,0x80095448) */
/* WARNING: Removing unreachable block (ram,0x80095440) */
/* WARNING: Removing unreachable block (ram,0x80095438) */
/* WARNING: Removing unreachable block (ram,0x80095430) */
/* WARNING: Removing unreachable block (ram,0x80095428) */
/* WARNING: Removing unreachable block (ram,0x80095420) */
/* WARNING: Removing unreachable block (ram,0x80095418) */
/* WARNING: Removing unreachable block (ram,0x80095410) */
/* WARNING: Removing unreachable block (ram,0x80095408) */
/* WARNING: Removing unreachable block (ram,0x80095400) */

void FUN_800953f0(void)

{
  float fVar1;
  float *pfVar2;
  float *pfVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double in_f20;
  double dVar12;
  double in_f21;
  double in_f22;
  double dVar13;
  double in_f23;
  double dVar14;
  double in_f24;
  double dVar15;
  double in_f25;
  double in_f26;
  double dVar16;
  double in_f27;
  double dVar17;
  double in_f28;
  double dVar18;
  double in_f29;
  double dVar19;
  double in_f30;
  double dVar20;
  double in_f31;
  double dVar21;
  double in_ps20_1;
  double in_ps21_1;
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
  float afStack_1a8 [12];
  float afStack_178 [12];
  float afStack_148 [12];
  float afStack_118 [12];
  undefined4 local_e8;
  uint uStack_e4;
  longlong local_e0;
  float local_b8;
  float fStack_b4;
  float local_a8;
  float fStack_a4;
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
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  pfVar2 = (float *)FUN_80286840();
  dVar8 = (double)pfVar2[3];
  FUN_80247a7c(dVar8,dVar8,dVar8,afStack_148);
  uVar4 = 0;
  iVar6 = 0;
  dVar14 = (double)FLOAT_803dff60;
  dVar15 = (double)FLOAT_803dff64;
  dVar16 = (double)FLOAT_803dff78;
  dVar17 = (double)FLOAT_803dff68;
  dVar18 = (double)FLOAT_803dff70;
  dVar19 = (double)FLOAT_803dff6c;
  dVar20 = (double)FLOAT_803dff74;
  dVar21 = (double)FLOAT_803dff7c;
  dVar12 = (double)FLOAT_803dff84;
  pfVar5 = pfVar2;
  dVar8 = DOUBLE_803dff88;
  do {
    dVar9 = (double)pfVar2[4];
    uStack_e4 = uVar4 ^ 0x80000000;
    local_e8 = 0x43300000;
    dVar11 = (double)(float)(dVar15 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                       uStack_e4) -
                                                                     dVar8) / dVar16));
    dVar10 = (double)(float)((double)(float)(dVar14 + dVar11) * dVar9);
    fVar1 = (float)(dVar10 - dVar17);
    dVar13 = -(double)(float)(dVar18 * (double)(fVar1 * fVar1) - dVar19);
    dVar7 = (double)(float)(dVar20 + dVar11);
    dVar11 = dVar19;
    if (dVar7 <= dVar9) {
      dVar11 = (double)((float)(dVar19 - dVar9) / (float)(dVar19 - dVar7));
    }
    dVar7 = (double)(float)(dVar21 * dVar10 + dVar19);
    FUN_80247a7c(dVar7,dVar19,dVar7,afStack_178);
    FUN_80247a48((double)FLOAT_803dff80,(double)(float)(dVar21 * dVar13),(double)FLOAT_803dff80,
                 afStack_1a8);
    FUN_80247618(afStack_1a8,afStack_178,afStack_118);
    FUN_80247618(afStack_148,afStack_118,afStack_118);
    FUN_80247a48((double)(*pfVar2 - FLOAT_803dda58),(double)pfVar2[1],
                 (double)(pfVar2[2] - FLOAT_803dda5c),afStack_1a8);
    FUN_80247618(afStack_1a8,afStack_118,afStack_118);
    pfVar3 = (float *)FUN_8000f56c();
    FUN_80247618(pfVar3,afStack_118,afStack_118);
    FUN_8025d80c(afStack_118,iVar6);
    local_e0 = (longlong)(int)(dVar12 * dVar11);
    pfVar5[6] = (float)((int)(dVar12 * dVar11) & 0xff);
    iVar6 = iVar6 + 3;
    pfVar5 = pfVar5 + 1;
    uVar4 = uVar4 + 1;
  } while ((int)uVar4 < 8);
  FUN_80242114((uint)(pfVar2 + 6),0x20);
  FUN_802585d8(0xb,(uint)(pfVar2 + 6),4);
  FUN_80259288(1);
  FUN_8025d63c(DAT_803dde88,(uint)DAT_803dde84);
  FUN_80259288(2);
  FUN_8025d63c(DAT_803dde88,(uint)DAT_803dde84);
  FUN_8028688c();
  return;
}

