// Function: FUN_800348b0
// Entry: 800348b0
// Size: 1068 bytes

void FUN_800348b0(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 *puVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  undefined4 *puVar17;
  int iVar18;
  undefined *puVar19;
  undefined *puVar20;
  float *pfVar21;
  float *pfVar22;
  int iVar23;
  undefined8 uVar24;
  undefined auStack328 [24];
  float local_130 [18];
  float local_e8 [18];
  undefined auStack160 [64];
  float local_60 [4];
  undefined local_50 [12];
  int local_44 [5];
  undefined4 local_30;
  uint uStack44;
  
  uVar24 = FUN_802860cc();
  iVar23 = (int)((ulonglong)uVar24 >> 0x20);
  iVar5 = (int)uVar24;
  iVar6 = *(int *)(iVar23 + 0x54);
  if (iVar5 == iVar23) {
    uVar2 = *(uint *)(iVar6 + 0x48) >> 4;
  }
  else {
    uVar2 = *(uint *)(iVar6 + 0x48) & 0xf;
  }
  if ((uVar2 != 0) && (*(char *)(iVar6 + 0x70) == '\0')) {
    iVar6 = *(int *)(iVar5 + 0x54);
    if ((*(byte *)(iVar6 + 0xb6) & 0x10) == 0) {
      local_e8[0] = *(float *)(iVar23 + 0x18);
      local_e8[1] = *(float *)(iVar23 + 0x1c);
      local_e8[2] = *(float *)(iVar23 + 0x20);
      local_130[0] = *(float *)(iVar23 + 0x8c);
      local_130[1] = *(float *)(iVar23 + 0x90);
      local_130[2] = *(float *)(iVar23 + 0x94);
      uStack44 = (uint)*(byte *)(*(int *)(iVar23 + 0x50) + 0x8f);
      local_30 = 0x43300000;
      local_60[0] = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de950);
      if (local_60[0] < FLOAT_803de91c) {
        local_60[0] = FLOAT_803de91c;
      }
      local_50[0] = 0xff;
      local_50[4] = 7;
      iVar23 = 1;
    }
    else {
      piVar9 = *(int **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
      iVar12 = *piVar9;
      uVar7 = *(ushort *)(piVar9 + 6) >> 2 & 1;
      puVar13 = (undefined4 *)piVar9[uVar7 + 0x12];
      iVar14 = piVar9[(uVar7 ^ 1) + 0x12];
      iVar23 = 0;
      iVar15 = 0;
      iVar16 = 0;
      iVar3 = 0;
      puVar8 = puVar13;
      iVar10 = iVar14;
      for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar12 + 0xf7); iVar11 = iVar11 + 1) {
        iVar18 = *(int *)(iVar12 + 0x58) + iVar3;
        if ((iVar11 == *(char *)(iVar18 + 0x16)) &&
           ((uVar2 & 1 << (int)*(char *)(iVar18 + 0x17)) != 0)) {
          uVar7 = (uint)*(ushort *)(iVar18 + 0x14);
          if (uVar7 == 0) {
            if (iVar23 < 4) {
              *(float *)((int)local_e8 + iVar16) = FLOAT_803dcdd8 + (float)puVar8[1];
              *(undefined4 *)((int)local_e8 + iVar16 + 4) = puVar8[2];
              *(float *)((int)local_e8 + iVar16 + 8) = FLOAT_803dcddc + (float)puVar8[3];
              *(float *)((int)local_130 + iVar16) = FLOAT_803dcdd8 + *(float *)(iVar10 + 4);
              *(undefined4 *)((int)local_130 + iVar16 + 4) = *(undefined4 *)(iVar10 + 8);
              *(float *)((int)local_130 + iVar16 + 8) = FLOAT_803dcddc + *(float *)(iVar10 + 0xc);
              *(undefined4 *)((int)local_60 + iVar15) = *puVar8;
              local_50[iVar23] = 0xff;
              local_50[iVar23 + 4] = 7;
              iVar23 = iVar23 + 1;
              iVar15 = iVar15 + 4;
              iVar16 = iVar16 + 0xc;
            }
          }
          else {
            pfVar22 = (float *)((int)local_e8 + iVar16);
            pfVar21 = (float *)((int)local_130 + iVar16);
            puVar20 = auStack160 + iVar15;
            puVar19 = auStack160 + iVar23;
            for (; uVar7 != 0; uVar7 = (uVar7 & 0xfff) << 4) {
              uVar1 = ((int)(uVar7 & 0xf000) >> 0xc) + iVar11 & 0xffff;
              if (iVar23 < 4) {
                puVar17 = puVar13 + uVar1 * 4;
                *pfVar22 = FLOAT_803dcdd8 + (float)puVar17[1];
                pfVar22[1] = (float)puVar17[2];
                pfVar22[2] = FLOAT_803dcddc + (float)puVar17[3];
                iVar18 = iVar14 + uVar1 * 0x10;
                *pfVar21 = FLOAT_803dcdd8 + *(float *)(iVar18 + 4);
                pfVar21[1] = *(float *)(iVar18 + 8);
                pfVar21[2] = FLOAT_803dcddc + *(float *)(iVar18 + 0xc);
                *(undefined4 *)(puVar20 + 0x40) = *puVar17;
                puVar19[0x50] = 0xff;
                puVar19[0x54] = 7;
                pfVar22 = pfVar22 + 3;
                pfVar21 = pfVar21 + 3;
                puVar20 = puVar20 + 4;
                puVar19 = puVar19 + 1;
                iVar23 = iVar23 + 1;
                iVar15 = iVar15 + 4;
                iVar16 = iVar16 + 0xc;
              }
            }
          }
        }
        iVar3 = iVar3 + 0x18;
        puVar8 = puVar8 + 4;
        iVar10 = iVar10 + 0x10;
      }
    }
    if (iVar23 != 0) {
      FUN_8006961c(auStack328,local_130,local_e8,local_60,iVar23);
      FUN_800691c0(iVar5,auStack328,*(undefined2 *)(iVar6 + 0xb2),1);
      bVar4 = FUN_80067958(iVar5,local_130,local_e8,iVar23,auStack160,0);
      if (bVar4 != 0) {
        if ((bVar4 & 1) == 0) {
          if ((bVar4 & 2) == 0) {
            if ((bVar4 & 4) == 0) {
              iVar23 = 3;
            }
            else {
              iVar23 = 2;
            }
          }
          else {
            iVar23 = 1;
          }
        }
        else {
          iVar23 = 0;
        }
        *(undefined *)(iVar6 + 0xac) = local_50[iVar23];
        *(float *)(iVar6 + 0x3c) = local_e8[iVar23 * 3];
        *(float *)(iVar6 + 0x40) = local_e8[iVar23 * 3 + 1];
        *(float *)(iVar6 + 0x44) = local_e8[iVar23 * 3 + 2];
        if (local_44[iVar23] == 0) {
          *(byte *)(iVar6 + 0xad) = *(byte *)(iVar6 + 0xad) | 1;
        }
        else {
          *(byte *)(iVar6 + 0xad) = *(byte *)(iVar6 + 0xad) | 2;
        }
      }
    }
  }
  FUN_80286118();
  return;
}

