// Function: FUN_80174bfc
// Entry: 80174bfc
// Size: 1296 bytes

/* WARNING: Removing unreachable block (ram,0x801750e4) */
/* WARNING: Removing unreachable block (ram,0x801750d4) */
/* WARNING: Removing unreachable block (ram,0x801750dc) */
/* WARNING: Removing unreachable block (ram,0x801750ec) */

void FUN_80174bfc(void)

{
  short sVar1;
  byte bVar2;
  undefined2 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  float *pfVar14;
  undefined4 *puVar15;
  undefined4 uVar16;
  undefined8 in_f28;
  double dVar17;
  undefined8 in_f29;
  double dVar18;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  double dVar20;
  undefined8 uVar21;
  undefined2 local_190;
  undefined2 local_18e;
  undefined2 local_18c;
  float local_188;
  undefined4 local_184;
  undefined4 local_180;
  undefined4 local_17c;
  undefined auStack376 [48];
  undefined4 local_148;
  undefined4 local_144;
  undefined4 local_140;
  undefined auStack312 [28];
  float local_11c;
  float local_114;
  char local_e7;
  undefined4 local_e4 [21];
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar21 = FUN_802860bc();
  puVar3 = (undefined2 *)((ulonglong)uVar21 >> 0x20);
  iVar7 = (int)uVar21;
  iVar12 = *(int *)(puVar3 + 0x26);
  FUN_8002b9ec();
  dVar19 = (double)*(float *)(puVar3 + 6);
  dVar18 = (double)*(float *)(puVar3 + 8);
  dVar17 = (double)*(float *)(puVar3 + 10);
  bVar2 = 0xf;
  iVar10 = 0;
  dVar20 = (double)FLOAT_803e3588;
  do {
    if (bVar2 == 0) {
LAB_801750bc:
      FUN_80003494(iVar7 + 0x78,local_e4,*(char *)(iVar7 + 0xb4) * 0xc);
      __psq_l0(auStack8,uVar16);
      __psq_l1(auStack8,uVar16);
      __psq_l0(auStack24,uVar16);
      __psq_l1(auStack24,uVar16);
      __psq_l0(auStack40,uVar16);
      __psq_l1(auStack40,uVar16);
      __psq_l0(auStack56,uVar16);
      __psq_l1(auStack56,uVar16);
      FUN_80286108();
      return;
    }
    bVar2 = 0xf;
    iVar10 = iVar10 + 1;
    if (4 < iVar10) {
      *(float *)(puVar3 + 6) = (float)dVar19;
      *(float *)(puVar3 + 8) = (float)dVar18;
      *(float *)(puVar3 + 10) = (float)dVar17;
      goto LAB_801750bc;
    }
    iVar9 = 8;
    iVar8 = 4;
    puVar15 = local_e4;
    iVar13 = iVar7;
    pfVar14 = (float *)(iVar7 + 0x18);
    for (iVar11 = 0; iVar11 < *(char *)(iVar7 + 0xb4); iVar11 = iVar11 + 1) {
      local_190 = *puVar3;
      local_18e = puVar3[1];
      local_18c = puVar3[2];
      local_188 = (float)dVar20;
      local_184 = *(undefined4 *)(puVar3 + 6);
      local_180 = *(undefined4 *)(puVar3 + 8);
      local_17c = *(undefined4 *)(puVar3 + 10);
      FUN_80021ee8(auStack376,&local_190);
      FUN_800226cc((double)*pfVar14,(double)pfVar14[1],(double)pfVar14[2],auStack376,puVar15,
                   (int)local_e4 + iVar8,(int)local_e4 + iVar9);
      if ((1 << iVar11 & 0xfU) != 0) {
        iVar4 = FUN_800640cc((double)FLOAT_803e358c,iVar13 + 0x78,puVar15,1,auStack312,puVar3,8,0xd,
                             iVar11 + 3U & 0xff,10);
        if (iVar4 == 0) {
          bVar2 = bVar2 & ~(byte)(1 << iVar11);
        }
        else {
          if ((local_e7 != -1) && ((*(ushort *)(iVar7 + 0x100) & 1) == 0)) {
            *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 1;
            iVar4 = (int)*(short *)(iVar12 + 0x18);
            if (-1 < iVar4) {
              sVar1 = puVar3[0x23];
              if (sVar1 != 0x411) {
                if (sVar1 < 0x411) {
                  if (sVar1 != 0x21e) {
                    if ((0x21d < sVar1) || (sVar1 != 0x1cb)) goto LAB_80174e90;
                    if (local_e7 == '\x01') {
                      FUN_800200e8(iVar4,1);
                      FUN_8000bb18(0,0x109);
                      *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x80;
                      *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
                      FUN_800e8370(puVar3);
                    }
                  }
                }
                else if (sVar1 == 0x7df) {
                  *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) & 0xfffe;
                  if ((int)local_e7 == (uint)*(byte *)(iVar7 + 0x144)) {
                    puVar5 = (undefined4 *)FUN_800394ac(puVar3,0,0);
                    if (puVar5 != (undefined4 *)0x0) {
                      *puVar5 = 0x100;
                    }
                    FUN_800200e8((int)*(short *)(iVar12 + 0x18),1);
                    *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
                    *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x80;
                  }
                }
                else {
LAB_80174e90:
                  if ((-1 < *(char *)(iVar12 + 0x23)) && (*(char *)(iVar12 + 0x23) == local_e7)) {
                    FUN_800200e8(iVar4,1);
                    FUN_8000bb18(0,0x109);
                  }
                }
              }
            }
          }
          uStack140 = *(uint *)(iVar7 + 0x140) ^ 0x80000000;
          local_90 = 0x43300000;
          FUN_80293e80((double)((FLOAT_803e3590 *
                                (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e3578)) /
                               FLOAT_803e3594));
          uStack132 = *(uint *)(iVar7 + 0x140) ^ 0x80000000;
          local_88 = 0x43300000;
          FUN_80294204((double)((FLOAT_803e3590 *
                                (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e3578)) /
                               FLOAT_803e3594));
          uVar6 = FUN_800217c0((double)local_11c,(double)local_114);
          iVar4 = *(int *)(iVar7 + 0x140) - (uVar6 & 0xffff);
          if (0x8000 < iVar4) {
            iVar4 = iVar4 + -0xffff;
          }
          if (iVar4 < -0x8000) {
            iVar4 = iVar4 + 0xffff;
          }
          iVar4 = iVar4 / 0xb6 + (iVar4 >> 0x1f);
          iVar4 = iVar4 - (iVar4 >> 0x1f);
          if ((iVar4 < -0x1d) || (0x1d < iVar4)) {
            if ((iVar4 < 0x97) && (-0x97 < iVar4)) {
              if ((iVar4 < 0x3d) || (0x77 < iVar4)) {
                if ((iVar4 < -0x3c) && (-0x78 < iVar4)) {
                  *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x400;
                  *(float *)(iVar7 + 0x10c) = FLOAT_803e3528;
                }
              }
              else {
                *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x800;
                *(float *)(iVar7 + 0x10c) = FLOAT_803e3528;
              }
            }
            else {
              *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x200;
              *(float *)(iVar7 + 0x108) = FLOAT_803e3528;
            }
          }
          else {
            *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x100;
            *(float *)(iVar7 + 0x108) = FLOAT_803e3528;
          }
          FUN_80003494(iVar13 + 0x78,puVar15,0xc);
          local_148 = *puVar15;
          local_144 = puVar15[1];
          local_140 = puVar15[2];
          FUN_800226cc(-(double)*pfVar14,-(double)pfVar14[1],-(double)pfVar14[2],auStack376,
                       puVar3 + 6,puVar3 + 8,puVar3 + 10);
        }
      }
      iVar9 = iVar9 + 0xc;
      iVar8 = iVar8 + 0xc;
      puVar15 = puVar15 + 3;
      pfVar14 = pfVar14 + 3;
      iVar13 = iVar13 + 0xc;
    }
  } while( true );
}

