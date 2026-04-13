// Function: FUN_80096c3c
// Entry: 80096c3c
// Size: 740 bytes

/* WARNING: Removing unreachable block (ram,0x80096f00) */
/* WARNING: Removing unreachable block (ram,0x80096ef8) */
/* WARNING: Removing unreachable block (ram,0x80096ef0) */
/* WARNING: Removing unreachable block (ram,0x80096ee8) */
/* WARNING: Removing unreachable block (ram,0x80096ee0) */
/* WARNING: Removing unreachable block (ram,0x80096ed8) */
/* WARNING: Removing unreachable block (ram,0x80096ed0) */
/* WARNING: Removing unreachable block (ram,0x80096ec8) */
/* WARNING: Removing unreachable block (ram,0x80096ec0) */
/* WARNING: Removing unreachable block (ram,0x80096c8c) */
/* WARNING: Removing unreachable block (ram,0x80096c84) */
/* WARNING: Removing unreachable block (ram,0x80096c7c) */
/* WARNING: Removing unreachable block (ram,0x80096c74) */
/* WARNING: Removing unreachable block (ram,0x80096c6c) */
/* WARNING: Removing unreachable block (ram,0x80096c64) */
/* WARNING: Removing unreachable block (ram,0x80096c5c) */
/* WARNING: Removing unreachable block (ram,0x80096c54) */
/* WARNING: Removing unreachable block (ram,0x80096c4c) */

void FUN_80096c3c(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined4 param_6,undefined4 param_7,uint param_8)

{
  int iVar1;
  uint uVar2;
  ushort *puVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  ushort *puVar8;
  float *pfVar9;
  ushort *puVar10;
  double extraout_f1;
  double dVar11;
  double in_f23;
  double dVar12;
  double in_f24;
  double dVar13;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  undefined auStack_128 [8];
  float local_120;
  float local_11c;
  float local_118;
  float local_114;
  undefined4 local_110;
  uint uStack_10c;
  longlong local_108;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  longlong local_d8;
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
  uVar17 = FUN_80286820();
  iVar1 = (int)((ulonglong)uVar17 >> 0x20);
  puVar3 = (ushort *)uVar17;
  iVar6 = 0;
  pfVar9 = (float *)&DAT_80310598;
  psVar7 = (short *)&DAT_803dc3e8;
  dVar12 = (double)FLOAT_803dffdc;
  dVar13 = (double)FLOAT_803dffd4;
  dVar15 = (double)(float)((double)FLOAT_803dffd0 / extraout_f1);
  dVar16 = (double)FLOAT_803dffd8;
  puVar8 = puVar3;
  puVar10 = puVar3;
  dVar14 = DOUBLE_803dffe0;
  do {
    uVar2 = FUN_80022264(0x78,0x7f);
    uStack_10c = iVar6 * uVar2 ^ 0x80000000;
    local_110 = 0x43300000;
    iVar5 = (int)(dVar15 + (double)(float)((double)CONCAT44(0x43300000,uStack_10c) - dVar14));
    local_108 = (longlong)iVar5;
    puVar10[0x12] = (ushort)iVar5;
    uStack_fc = (int)(short)puVar10[0x12] ^ 0x80000000;
    local_100 = 0x43300000;
    uStack_f4 = (int)(short)puVar10[0xe] ^ 0x80000000;
    local_f8 = 0x43300000;
    iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack_fc) - dVar14) * FLOAT_803dc074 +
                 (float)((double)CONCAT44(0x43300000,uStack_f4) - dVar14));
    local_f0 = (longlong)iVar5;
    puVar10[0xe] = (ushort)iVar5;
    dVar11 = (double)FUN_80293a9c();
    *(float *)(puVar8 + 6) = *pfVar9 * (float)((double)(float)(dVar13 + dVar11) * dVar16);
    uStack_e4 = (int)*psVar7 ^ 0x80000000;
    local_e8 = 0x43300000;
    uStack_dc = (int)(short)puVar10[0x16] ^ 0x80000000;
    local_e0 = 0x43300000;
    iVar5 = (int)(FLOAT_803dc074 * (float)((double)CONCAT44(0x43300000,uStack_e4) - dVar14) +
                 (float)((double)CONCAT44(0x43300000,uStack_dc) - dVar14));
    local_d8 = (longlong)iVar5;
    puVar10[0x16] = (ushort)iVar5;
    *puVar3 = puVar10[0x16];
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(puVar8 + 6);
    for (iVar5 = 0; iVar5 < 0xffff; iVar5 = iVar5 + 0x7fff) {
      local_11c = (float)((double)*(float *)(puVar3 + 4) * param_2 + param_4);
      local_118 = (float)((double)*(float *)(puVar3 + 4) * param_3 + param_5);
      local_114 = (float)dVar12;
      *puVar3 = *puVar3 + 0x7fff;
      FUN_80021b8c(puVar3,&local_11c);
      local_11c = local_11c + *(float *)(iVar1 + 0xc);
      local_118 = local_118 + *(float *)(iVar1 + 0x10);
      local_114 = local_114 + *(float *)(iVar1 + 0x14);
      local_120 = (float)dVar13;
      uVar4 = 0x200001;
      if ((param_8 & 0xff) != 0) {
        uVar4 = 0x20200001;
      }
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0x7ec,auStack_128,uVar4,0xffffffff,0);
    }
    puVar10 = puVar10 + 1;
    pfVar9 = pfVar9 + 1;
    puVar8 = puVar8 + 2;
    psVar7 = psVar7 + 1;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 4);
  FUN_8028686c();
  return;
}

