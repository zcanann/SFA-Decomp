// Function: FUN_801010b4
// Entry: 801010b4
// Size: 1268 bytes

/* WARNING: Removing unreachable block (ram,0x80101588) */

void FUN_801010b4(void)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  int extraout_r4;
  uint uVar7;
  undefined4 *puVar8;
  int iVar9;
  int *piVar10;
  float *pfVar11;
  undefined4 *puVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  uint uVar16;
  int *piVar17;
  uint uVar18;
  undefined4 uVar19;
  undefined8 in_f31;
  double dVar20;
  char local_c8 [4];
  int local_c4;
  int local_c0;
  undefined auStack188 [12];
  undefined auStack176 [12];
  undefined local_a4 [12];
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  float local_88;
  undefined4 local_84;
  float local_80 [8];
  int local_60 [8];
  undefined4 local_40;
  uint uStack60;
  undefined auStack8 [8];
  
  uVar19 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_802860cc();
  uVar16 = 0xffffffff;
  iVar14 = 0;
  iVar13 = 0;
  iVar4 = FUN_8002b9ec();
  if ((((iVar4 == 0) || (extraout_r4 == 0)) || (DAT_803dd518 == 0x44)) ||
     (iVar5 = FUN_80296328(), iVar5 == 0)) {
    local_60[0] = 0;
  }
  else {
    iVar5 = FUN_8002e0fc(&local_c0,&local_c4);
    piVar17 = (int *)(iVar5 + local_c0 * 4);
    for (; local_c0 < local_c4; local_c0 = local_c0 + 1) {
      iVar15 = *piVar17;
      iVar5 = *(int *)(iVar15 + 0x78);
      if ((((iVar5 == 0) || (*(char *)(iVar15 + 0x36) != -1)) ||
          (((*(byte *)(iVar15 + 0xaf) & 0x28) != 0 ||
           (((*(ushort *)(iVar15 + 0xb0) & 0x800) == 0 &&
            ((*(uint *)(*(int *)(iVar15 + 0x50) + 0x44) & 1) == 0)))))) ||
         (((*(ushort *)(iVar15 + 6) & 0x4000) != 0 ||
          (((*(ushort *)(iVar15 + 0xb0) & 0x40) != 0 ||
           (bVar3 = true,
           ((uint)DAT_803db992 &
           1 << (*(byte *)(iVar5 + (uint)*(byte *)(iVar15 + 0xe4) * 5 + 4) & 0xf)) == 0)))))) {
        bVar3 = false;
      }
      if (bVar3) {
        uVar7 = (uint)*(byte *)(iVar15 + 0xe4);
        iVar9 = uVar7 * 0x18;
        if ((int)uVar16 <=
            (int)(uint)*(byte *)(*(int *)(*(int *)(iVar15 + 0x50) + 0x40) + iVar9 + 0x11)) {
          fVar1 = FLOAT_803e1630;
          if (((*(byte *)(iVar15 + 0xaf) & 0x80) == 0) &&
             ((*(byte *)(iVar5 + uVar7 * 5 + 4) & 0x80) == 0)) {
            fVar1 = *(float *)(extraout_r4 + 0x1c) -
                    *(float *)(*(int *)(iVar15 + 0x74) + iVar9 + 0x10);
          }
          if ((FLOAT_803e1644 < fVar1) && (fVar1 < FLOAT_803e1648)) {
            iVar9 = *(int *)(iVar15 + 0x74) + iVar9;
            fVar1 = *(float *)(extraout_r4 + 0x18) - *(float *)(iVar9 + 0xc);
            fVar2 = *(float *)(extraout_r4 + 0x20) - *(float *)(iVar9 + 0x14);
            dVar20 = (double)(fVar1 * fVar1 + fVar2 * fVar2);
            iVar5 = iVar5 + uVar7 * 5;
            uStack60 = (uint)*(byte *)(iVar5 + 2) << 2 ^ 0x80000000;
            local_40 = 0x43300000;
            fVar1 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1650);
            if (dVar20 < (double)(fVar1 * fVar1)) {
              bVar3 = true;
              if (((*(byte *)(iVar5 + 4) & 0xf) == 2) && (iVar5 = FUN_80295c24(iVar4), iVar5 != 0))
              {
                bVar3 = false;
              }
              if (bVar3) {
                uVar16 = (uint)*(byte *)(*(int *)(*(int *)(iVar15 + 0x50) + 0x40) +
                                        (uint)*(byte *)(iVar15 + 0xe4) * 0x18 + 0x11);
                iVar5 = 0;
                piVar10 = local_60;
                while ((iVar5 < iVar14 &&
                       (uVar16 < *(byte *)(*(int *)(*(int *)(*piVar10 + 0x50) + 0x40) +
                                          (uint)*(byte *)(*piVar10 + 0xe4) * 0x18 + 0x11)))) {
                  piVar10 = piVar10 + 1;
                  iVar5 = iVar5 + 1;
                }
                pfVar11 = local_80 + iVar5;
                piVar10 = local_60 + iVar5;
                while (((iVar5 < iVar14 && ((double)*pfVar11 < dVar20)) &&
                       (uVar16 == *(byte *)(*(int *)(*(int *)(*piVar10 + 0x50) + 0x40) +
                                           (uint)*(byte *)(*piVar10 + 0xe4) * 0x18 + 0x11)))) {
                  pfVar11 = pfVar11 + 1;
                  piVar10 = piVar10 + 1;
                  iVar5 = iVar5 + 1;
                }
                puVar8 = (undefined4 *)((int)local_80 + iVar13);
                puVar12 = (undefined4 *)((int)local_60 + iVar13);
                uVar7 = iVar14 - iVar5;
                if (iVar5 < iVar14) {
                  uVar18 = uVar7 >> 3;
                  if (uVar18 != 0) {
                    do {
                      *puVar8 = puVar8[-1];
                      *puVar12 = puVar12[-1];
                      puVar8[-1] = puVar8[-2];
                      puVar12[-1] = puVar12[-2];
                      puVar8[-2] = puVar8[-3];
                      puVar12[-2] = puVar12[-3];
                      puVar8[-3] = puVar8[-4];
                      puVar12[-3] = puVar12[-4];
                      puVar8[-4] = puVar8[-5];
                      puVar12[-4] = puVar12[-5];
                      puVar8[-5] = puVar8[-6];
                      puVar12[-5] = puVar12[-6];
                      puVar8[-6] = puVar8[-7];
                      puVar12[-6] = puVar12[-7];
                      puVar8[-7] = puVar8[-8];
                      puVar12[-7] = puVar12[-8];
                      puVar8 = puVar8 + -8;
                      puVar12 = puVar12 + -8;
                      uVar18 = uVar18 - 1;
                    } while (uVar18 != 0);
                    uVar7 = uVar7 & 7;
                    if (uVar7 == 0) goto LAB_80101484;
                  }
                  do {
                    *puVar8 = puVar8[-1];
                    *puVar12 = puVar12[-1];
                    puVar8 = puVar8 + -1;
                    puVar12 = puVar12 + -1;
                    uVar7 = uVar7 - 1;
                  } while (uVar7 != 0);
                }
LAB_80101484:
                local_80[iVar5] = (float)dVar20;
                local_60[iVar5] = iVar15;
                iVar14 = iVar14 + 1;
                iVar13 = iVar13 + 4;
                if (iVar14 == 8) break;
              }
            }
          }
        }
      }
      piVar17 = piVar17 + 1;
    }
    if (iVar14 < 1) {
      local_60[0] = 0;
    }
    else {
      iVar4 = (uint)*(byte *)(local_60[0] + 0xe4) * 0x18;
      if ((*(byte *)(*(int *)(*(int *)(local_60[0] + 0x50) + 0x40) + iVar4 + 0x10) & 0x20) != 0) {
        local_8c = *(undefined4 *)(extraout_r4 + 0x18);
        local_88 = FLOAT_803e1648 + *(float *)(extraout_r4 + 0x1c);
        local_84 = *(undefined4 *)(extraout_r4 + 0x20);
        local_98 = *(undefined4 *)(*(int *)(local_60[0] + 0x74) + iVar4);
        iVar4 = *(int *)(local_60[0] + 0x74) + iVar4;
        local_94 = *(undefined4 *)(iVar4 + 4);
        local_90 = *(undefined4 *)(iVar4 + 8);
        FUN_80012d00(&local_8c,local_a4);
        FUN_80012d00(&local_98,auStack176);
        cVar6 = FUN_800128dc(local_a4,auStack176,auStack188,local_c8,0);
        if ((cVar6 == '\0') && (local_c8[0] != '\x01')) {
          local_60[0] = 0;
        }
      }
    }
  }
  __psq_l0(auStack8,uVar19);
  __psq_l1(auStack8,uVar19);
  FUN_80286118(local_60[0]);
  return;
}

