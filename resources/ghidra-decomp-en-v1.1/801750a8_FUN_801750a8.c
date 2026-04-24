// Function: FUN_801750a8
// Entry: 801750a8
// Size: 1296 bytes

/* WARNING: Removing unreachable block (ram,0x80175598) */
/* WARNING: Removing unreachable block (ram,0x80175590) */
/* WARNING: Removing unreachable block (ram,0x80175588) */
/* WARNING: Removing unreachable block (ram,0x80175580) */
/* WARNING: Removing unreachable block (ram,0x801750d0) */
/* WARNING: Removing unreachable block (ram,0x801750c8) */
/* WARNING: Removing unreachable block (ram,0x801750c0) */
/* WARNING: Removing unreachable block (ram,0x801750b8) */

void FUN_801750a8(void)

{
  ushort uVar1;
  byte bVar2;
  ushort *puVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  float *pfVar14;
  float *pfVar15;
  double in_f28;
  double dVar16;
  double in_f29;
  double dVar17;
  double in_f30;
  double dVar18;
  double in_f31;
  double dVar19;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
  ushort local_190;
  ushort local_18e;
  ushort local_18c;
  float local_188;
  int local_184;
  int local_180;
  int local_17c;
  float afStack_178 [12];
  float local_148;
  float local_144;
  float local_140;
  int aiStack_138 [20];
  char local_e7;
  float local_e4 [21];
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
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
  uVar20 = FUN_80286820();
  puVar3 = (ushort *)((ulonglong)uVar20 >> 0x20);
  iVar7 = (int)uVar20;
  iVar12 = *(int *)(puVar3 + 0x26);
  FUN_8002bac4();
  dVar18 = (double)*(float *)(puVar3 + 6);
  dVar17 = (double)*(float *)(puVar3 + 8);
  dVar16 = (double)*(float *)(puVar3 + 10);
  bVar2 = 0xf;
  iVar10 = 0;
  dVar19 = (double)FLOAT_803e4220;
  do {
    if (bVar2 == 0) {
LAB_80175568:
      FUN_80003494(iVar7 + 0x78,(uint)local_e4,*(char *)(iVar7 + 0xb4) * 0xc);
      FUN_8028686c();
      return;
    }
    bVar2 = 0xf;
    iVar10 = iVar10 + 1;
    if (4 < iVar10) {
      *(float *)(puVar3 + 6) = (float)dVar18;
      *(float *)(puVar3 + 8) = (float)dVar17;
      *(float *)(puVar3 + 10) = (float)dVar16;
      goto LAB_80175568;
    }
    iVar9 = 8;
    iVar8 = 4;
    pfVar15 = local_e4;
    iVar13 = iVar7;
    pfVar14 = (float *)(iVar7 + 0x18);
    for (iVar11 = 0; iVar11 < *(char *)(iVar7 + 0xb4); iVar11 = iVar11 + 1) {
      local_190 = *puVar3;
      local_18e = puVar3[1];
      local_18c = puVar3[2];
      local_188 = (float)dVar19;
      local_184 = *(int *)(puVar3 + 6);
      local_180 = *(int *)(puVar3 + 8);
      local_17c = *(int *)(puVar3 + 10);
      FUN_80021fac(afStack_178,&local_190);
      FUN_80022790((double)*pfVar14,(double)pfVar14[1],(double)pfVar14[2],afStack_178,pfVar15,
                   (float *)((int)local_e4 + iVar8),(float *)((int)local_e4 + iVar9));
      if ((1 << iVar11 & 0xfU) != 0) {
        iVar4 = FUN_80064248(iVar13 + 0x78,pfVar15,(float *)0x1,aiStack_138,(int *)puVar3,8,0xd,
                             iVar11 + 3U & 0xff,10);
        if (iVar4 == 0) {
          bVar2 = bVar2 & ~(byte)(1 << iVar11);
        }
        else {
          if ((local_e7 != -1) && ((*(ushort *)(iVar7 + 0x100) & 1) == 0)) {
            *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 1;
            uVar5 = (uint)*(short *)(iVar12 + 0x18);
            if (-1 < (int)uVar5) {
              uVar1 = puVar3[0x23];
              if (uVar1 != 0x411) {
                if ((short)uVar1 < 0x411) {
                  if (uVar1 != 0x21e) {
                    if ((0x21d < (short)uVar1) || (uVar1 != 0x1cb)) goto LAB_8017533c;
                    if (local_e7 == '\x01') {
                      FUN_800201ac(uVar5,1);
                      FUN_8000bb38(0,0x109);
                      *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x80;
                      *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
                      FUN_800e85f4((int)puVar3);
                    }
                  }
                }
                else if (uVar1 == 0x7df) {
                  *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) & 0xfffe;
                  if ((int)local_e7 == (uint)*(byte *)(iVar7 + 0x144)) {
                    puVar6 = (undefined4 *)FUN_800395a4((int)puVar3,0);
                    if (puVar6 != (undefined4 *)0x0) {
                      *puVar6 = 0x100;
                    }
                    FUN_800201ac((int)*(short *)(iVar12 + 0x18),1);
                    *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 8;
                    *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x80;
                  }
                }
                else {
LAB_8017533c:
                  if ((-1 < *(char *)(iVar12 + 0x23)) && (*(char *)(iVar12 + 0x23) == local_e7)) {
                    FUN_800201ac(uVar5,1);
                    FUN_8000bb38(0,0x109);
                  }
                }
              }
            }
          }
          uStack_8c = *(uint *)(iVar7 + 0x140) ^ 0x80000000;
          local_90 = 0x43300000;
          FUN_802945e0();
          uStack_84 = *(uint *)(iVar7 + 0x140) ^ 0x80000000;
          local_88 = 0x43300000;
          FUN_80294964();
          uVar5 = FUN_80021884();
          iVar4 = *(int *)(iVar7 + 0x140) - (uVar5 & 0xffff);
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
                  *(float *)(iVar7 + 0x10c) = FLOAT_803e41c0;
                }
              }
              else {
                *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x800;
                *(float *)(iVar7 + 0x10c) = FLOAT_803e41c0;
              }
            }
            else {
              *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x200;
              *(float *)(iVar7 + 0x108) = FLOAT_803e41c0;
            }
          }
          else {
            *(ushort *)(iVar7 + 0x100) = *(ushort *)(iVar7 + 0x100) | 0x100;
            *(float *)(iVar7 + 0x108) = FLOAT_803e41c0;
          }
          FUN_80003494(iVar13 + 0x78,(uint)pfVar15,0xc);
          local_148 = *pfVar15;
          local_144 = pfVar15[1];
          local_140 = pfVar15[2];
          FUN_80022790(-(double)*pfVar14,-(double)pfVar14[1],-(double)pfVar14[2],afStack_178,
                       (float *)(puVar3 + 6),(float *)(puVar3 + 8),(float *)(puVar3 + 10));
        }
      }
      iVar9 = iVar9 + 0xc;
      iVar8 = iVar8 + 0xc;
      pfVar15 = pfVar15 + 3;
      pfVar14 = pfVar14 + 3;
      iVar13 = iVar13 + 0xc;
    }
  } while( true );
}

