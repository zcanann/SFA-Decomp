// Function: FUN_8010bd34
// Entry: 8010bd34
// Size: 1128 bytes

/* WARNING: Removing unreachable block (ram,0x8010c17c) */
/* WARNING: Removing unreachable block (ram,0x8010c174) */
/* WARNING: Removing unreachable block (ram,0x8010c16c) */
/* WARNING: Removing unreachable block (ram,0x8010c164) */
/* WARNING: Removing unreachable block (ram,0x8010c15c) */
/* WARNING: Removing unreachable block (ram,0x8010c154) */
/* WARNING: Removing unreachable block (ram,0x8010c14c) */
/* WARNING: Removing unreachable block (ram,0x8010bd74) */
/* WARNING: Removing unreachable block (ram,0x8010bd6c) */
/* WARNING: Removing unreachable block (ram,0x8010bd64) */
/* WARNING: Removing unreachable block (ram,0x8010bd5c) */
/* WARNING: Removing unreachable block (ram,0x8010bd54) */
/* WARNING: Removing unreachable block (ram,0x8010bd4c) */
/* WARNING: Removing unreachable block (ram,0x8010bd44) */

void FUN_8010bd34(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  short sVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  short sVar7;
  short sVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f25;
  double dVar15;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar16;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  undefined4 local_148;
  undefined4 local_144;
  float afStack_140 [4];
  float afStack_130 [4];
  float afStack_120 [4];
  float afStack_110 [4];
  float afStack_100 [4];
  float afStack_f0 [4];
  float afStack_e0 [4];
  undefined auStack_d0 [16];
  undefined4 auStack_c0 [4];
  float local_b0;
  float local_ac;
  float local_a8;
  longlong local_a0;
  undefined8 local_98;
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
  uVar17 = FUN_8028683c();
  psVar2 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar6 = *(int *)(psVar2 + 0x52);
  if (DAT_803de1d8 == 0) {
    DAT_803de1d8 = FUN_80023d8c(0x68,0xf);
  }
  FUN_800033a8(DAT_803de1d8,0,0x68);
  *(undefined4 *)(DAT_803de1d8 + 4) = *param_3;
  *(undefined *)(DAT_803de1d8 + 100) = 1;
  local_148 = 9;
  local_144 = 0x1b;
  uVar3 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                     (double)*(float *)(iVar6 + 0x20),&local_148,2,*(undefined4 *)(DAT_803de1d8 + 4)
                    );
  *(undefined4 *)(DAT_803de1d8 + 0xc) = uVar3;
  local_148 = 8;
  local_144 = 0x1a;
  iVar5 = *DAT_803dd71c;
  uVar3 = (**(code **)(iVar5 + 0x14))
                    ((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                     (double)*(float *)(iVar6 + 0x20),&local_148,2,*(undefined4 *)(DAT_803de1d8 + 4)
                    );
  *(undefined4 *)(DAT_803de1d8 + 8) = uVar3;
  dVar13 = (double)*(float *)(iVar6 + 0x1c);
  dVar14 = (double)*(float *)(iVar6 + 0x20);
  FUN_8010a3a0((double)*(float *)(iVar6 + 0x18),dVar13,dVar14,in_f4,in_f5,in_f6,in_f7,in_f8,
               DAT_803de1d8 + 0xc,DAT_803de1d8 + 8,*(uint *)(DAT_803de1d8 + 4),iVar5,param_5,param_6
               ,param_7,param_8);
  iVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(DAT_803de1d8 + 8));
  uVar3 = (**(code **)(*DAT_803dd71c + 0x1c))(*(undefined4 *)(DAT_803de1d8 + 0xc));
  uVar9 = FUN_8010acf0(extraout_f1,dVar13,dVar14,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,auStack_d0,
                       *(uint *)(DAT_803de1d8 + 4),iVar5,param_5,param_6,param_7,param_8);
  FUN_8010acf0(uVar9,dVar13,dVar14,in_f4,in_f5,in_f6,in_f7,in_f8,uVar3,auStack_c0,
               *(uint *)(DAT_803de1d8 + 4),iVar5,param_5,param_6,param_7,param_8);
  FUN_8010a82c(auStack_d0,afStack_120,afStack_130,afStack_140,afStack_e0,afStack_f0,afStack_100,
               afStack_110);
  dVar14 = FUN_8010aee4((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                        (double)*(float *)(iVar6 + 0x20),auStack_c0);
  dVar13 = (double)FLOAT_803e2508;
  if ((dVar13 <= dVar14) && (dVar13 = dVar14, (double)FLOAT_803e250c < dVar14)) {
    dVar13 = (double)FLOAT_803e250c;
  }
  dVar14 = FUN_80010f00(dVar13,afStack_120,(float *)0x0);
  dVar10 = FUN_80010f00(dVar13,afStack_130,(float *)0x0);
  dVar11 = FUN_80010f00(dVar13,afStack_140,(float *)0x0);
  dVar16 = (double)(float)(dVar14 - (double)*(float *)(iVar6 + 0x18));
  dVar15 = (double)(float)(dVar11 - (double)*(float *)(iVar6 + 0x20));
  if ((*(byte *)(iVar4 + 0x3b) & 1) == 0) {
    dVar12 = FUN_80010c84(dVar13,afStack_e0,(float *)0x0);
    local_a0 = (longlong)(int)dVar12;
    sVar1 = (short)(int)dVar12;
  }
  else {
    iVar5 = FUN_80021884();
    sVar1 = -(short)iVar5;
  }
  if ((*(byte *)(iVar4 + 0x3b) & 4) == 0) {
    dVar12 = FUN_80010c84(dVar13,afStack_100,(float *)0x0);
    local_98 = (double)(longlong)(int)dVar12;
    sVar7 = (short)(int)dVar12;
  }
  else {
    sVar7 = *(short *)(iVar6 + 4);
  }
  if ((*(byte *)(iVar4 + 0x3b) & 2) == 0) {
    dVar15 = FUN_80010c84(dVar13,afStack_f0,(float *)0x0);
    local_98 = (double)(longlong)(int)dVar15;
    sVar8 = (short)(int)dVar15;
  }
  else {
    FUN_80293900((double)(float)(dVar16 * dVar16 + (double)(float)(dVar15 * dVar15)));
    iVar6 = FUN_80021884();
    dVar15 = FUN_80010c84(dVar13,afStack_f0,(float *)0x0);
    local_98 = (double)CONCAT44(0x43300000,(int)(short)iVar6 ^ 0x80000000);
    iVar6 = (int)((double)(float)(local_98 - DOUBLE_803e2520) - dVar15);
    local_a0 = (longlong)iVar6;
    sVar8 = (short)iVar6;
  }
  dVar15 = FUN_80010f00(dVar13,afStack_110,(float *)0x0);
  local_b0 = (float)dVar14;
  local_ac = (float)dVar10;
  local_a8 = (float)dVar11;
  if ((*(char *)(param_3 + 1) == '\0') && ((int)uVar17 != 3)) {
    FUN_8010b4d4(dVar15,psVar2,&local_b0,(int)(short)(sVar1 + -0x8000),(int)sVar8,(int)sVar7);
  }
  else {
    *(float *)(psVar2 + 0xc) = (float)dVar14;
    *(float *)(psVar2 + 0xe) = (float)dVar10;
    *(float *)(psVar2 + 0x10) = (float)dVar11;
    FUN_8000e054((double)*(float *)(psVar2 + 0xc),(double)*(float *)(psVar2 + 0xe),
                 (double)*(float *)(psVar2 + 0x10),(float *)(psVar2 + 6),(float *)(psVar2 + 8),
                 (float *)(psVar2 + 10),*(int *)(psVar2 + 0x18));
    *psVar2 = sVar1 + -0x8000;
    psVar2[1] = sVar8;
    psVar2[2] = sVar7;
    *(float *)(psVar2 + 0x5a) = (float)dVar15;
  }
  *(float *)(DAT_803de1d8 + 0x58) = (float)dVar13;
  FUN_80286888();
  return;
}

