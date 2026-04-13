// Function: FUN_80170f9c
// Entry: 80170f9c
// Size: 1148 bytes

/* WARNING: Removing unreachable block (ram,0x801713f8) */
/* WARNING: Removing unreachable block (ram,0x801713f0) */
/* WARNING: Removing unreachable block (ram,0x801713e8) */
/* WARNING: Removing unreachable block (ram,0x801713e0) */
/* WARNING: Removing unreachable block (ram,0x801713d8) */
/* WARNING: Removing unreachable block (ram,0x801713d0) */
/* WARNING: Removing unreachable block (ram,0x80170fd4) */
/* WARNING: Removing unreachable block (ram,0x80170fcc) */
/* WARNING: Removing unreachable block (ram,0x80170fc4) */
/* WARNING: Removing unreachable block (ram,0x80170fbc) */
/* WARNING: Removing unreachable block (ram,0x80170fb4) */
/* WARNING: Removing unreachable block (ram,0x80170fac) */

void FUN_80170f9c(void)

{
  byte bVar1;
  float fVar2;
  ushort uVar3;
  ushort uVar4;
  ushort uVar5;
  uint uVar6;
  ushort *puVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  char in_r8;
  byte bVar13;
  byte bVar14;
  uint uVar15;
  int iVar16;
  double in_f26;
  double dVar17;
  double in_f27;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined auStack_118 [8];
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
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
  undefined8 local_d0;
  undefined4 local_c8;
  uint uStack_c4;
  longlong local_c0;
  undefined4 local_b8;
  uint uStack_b4;
  undefined8 local_b0;
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
  puVar7 = (ushort *)FUN_80286814();
  iVar16 = *(int *)(puVar7 + 0x5c);
  if (in_r8 != '\0') {
    iVar8 = FUN_8002b660((int)puVar7);
    dVar22 = (double)*(float *)(puVar7 + 4);
    bVar1 = *(byte *)(puVar7 + 0x1b);
    uVar15 = (uint)bVar1;
    uVar3 = *puVar7;
    uVar4 = puVar7[1];
    uVar5 = puVar7[2];
    uVar9 = FUN_80020800();
    fVar2 = FLOAT_803dc074;
    if ((uVar9 & 0xff) != 0) {
      fVar2 = FLOAT_803e4044;
    }
    dVar21 = (double)fVar2;
    if (puVar7[0x23] == 0x836) {
      for (bVar14 = 0; bVar14 < 4; bVar14 = bVar14 + 1) {
        uVar9 = (uint)bVar14;
        if ((*(byte *)(iVar16 + uVar9 + 0x5c) & 1) == 0) {
          iVar12 = uVar9 * 2;
          iVar11 = iVar16 + iVar12;
          *puVar7 = *(ushort *)(iVar11 + 0x44);
          puVar7[1] = *(ushort *)(iVar11 + 0x4c);
          puVar7[2] = *(ushort *)(iVar11 + 0x54);
          dVar17 = DOUBLE_803e4068;
          uStack_fc = (int)*(short *)(&DAT_803dc9e0 + iVar12) ^ 0x80000000;
          local_100 = 0x43300000;
          uStack_f4 = (int)*(short *)(iVar11 + 0x44) ^ 0x80000000;
          local_f8 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)((double)CONCAT44(0x43300000,uStack_fc) -
                                                 DOUBLE_803e4068) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803e4068));
          local_f0 = (longlong)iVar10;
          *(short *)(iVar11 + 0x44) = (short)iVar10;
          uStack_e4 = (int)*(short *)(&DAT_803dc9e8 + iVar12) ^ 0x80000000;
          local_e8 = 0x43300000;
          uStack_dc = (int)*(short *)(iVar11 + 0x4c) ^ 0x80000000;
          local_e0 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)((double)CONCAT44(0x43300000,uStack_e4) - dVar17) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_dc) - dVar17));
          local_d8 = (longlong)iVar10;
          *(short *)(iVar11 + 0x4c) = (short)iVar10;
          local_d0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dc9f0 + iVar12) ^ 0x80000000);
          uStack_c4 = (int)*(short *)(iVar11 + 0x54) ^ 0x80000000;
          local_c8 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)(local_d0 - dVar17) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - dVar17));
          local_c0 = (longlong)iVar10;
          *(short *)(iVar11 + 0x54) = (short)iVar10;
          iVar10 = iVar16 + uVar9 * 4;
          *(float *)(puVar7 + 4) =
               (float)((double)*(float *)(iVar10 + 0x24) * dVar22) *
               (*(float *)(iVar16 + 4) / *(float *)(iVar16 + 0x10));
          local_b8 = 0x43300000;
          iVar10 = (int)(*(float *)(iVar10 + 0x14) *
                        (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e4078));
          local_b0 = (double)(longlong)iVar10;
          *(char *)((int)puVar7 + 0x37) = (char)iVar10;
          *(ushort *)(iVar8 + 0x18) = *(ushort *)(iVar8 + 0x18) & 0xfff7;
          uStack_b4 = uVar15;
          FUN_8003b9ec((int)puVar7);
        }
      }
    }
    else {
      for (bVar14 = 0; bVar14 < 4; bVar14 = bVar14 + 1) {
        uVar6 = (uint)bVar14;
        if ((*(byte *)(iVar16 + uVar6 + 0x5c) & 1) == 0) {
          iVar12 = uVar6 * 2 + 0x44;
          *puVar7 = *(ushort *)(iVar16 + iVar12);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dc9d8 + uVar6 * 2) ^ 0x80000000);
          uStack_b4 = (int)*(short *)(iVar16 + iVar12) ^ 0x80000000;
          local_b8 = 0x43300000;
          iVar10 = (int)(dVar21 * (double)(float)(local_b0 - DOUBLE_803e4068) +
                        (double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e4068));
          local_c0 = (longlong)iVar10;
          *(short *)(iVar16 + iVar12) = (short)iVar10;
          iVar10 = iVar16 + uVar6 * 4;
          *(float *)(puVar7 + 4) = (float)((double)*(float *)(iVar10 + 0x24) * dVar22);
          local_c8 = 0x43300000;
          iVar10 = (int)(*(float *)(iVar10 + 0x14) *
                        (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803e4078));
          local_d0 = (double)(longlong)iVar10;
          *(char *)((int)puVar7 + 0x37) = (char)iVar10;
          *(ushort *)(iVar8 + 0x18) = *(ushort *)(iVar8 + 0x18) & 0xfff7;
          uStack_c4 = uVar15;
          FUN_8003b9ec((int)puVar7);
          if ((uVar9 & 0xff) == 0) {
            dVar17 = (double)FLOAT_803e4070;
            dVar18 = (double)FLOAT_803e4074;
            dVar19 = (double)FLOAT_803e4044;
            dVar20 = (double)FLOAT_803e405c;
            for (bVar13 = 0; bVar13 < 2; bVar13 = bVar13 + 1) {
              local_10c = (float)(dVar17 * (double)*(float *)(puVar7 + 4));
              local_108 = (float)(dVar18 * (double)*(float *)(puVar7 + 4));
              local_104 = (float)dVar19;
              *puVar7 = *puVar7 + 0x7fff;
              FUN_80021b8c(puVar7,&local_10c);
              local_10c = local_10c + *(float *)(puVar7 + 6);
              local_108 = local_108 + *(float *)(puVar7 + 8);
              local_104 = local_104 + *(float *)(puVar7 + 10);
              local_110 = (float)dVar20;
              (**(code **)(*DAT_803dd708 + 8))(puVar7,0x7ec,auStack_118,0x200001,0xffffffff,0);
            }
          }
        }
      }
    }
    *(float *)(puVar7 + 4) = (float)dVar22;
    *(byte *)(puVar7 + 0x1b) = bVar1;
    *puVar7 = uVar3;
    puVar7[1] = uVar4;
    puVar7[2] = uVar5;
  }
  FUN_80286860();
  return;
}

