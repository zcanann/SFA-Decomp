// Function: FUN_80034cdc
// Entry: 80034cdc
// Size: 1736 bytes

/* WARNING: Removing unreachable block (ram,0x80035384) */

void FUN_80034cdc(void)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  float **ppfVar4;
  float *pfVar5;
  float **ppfVar6;
  float fVar7;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  float fVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  float **ppfVar17;
  undefined4 uVar18;
  double dVar19;
  undefined8 in_f31;
  undefined auStack4104 [216];
  undefined auStack3880 [4];
  undefined auStack3876 [4];
  undefined auStack3872 [100];
  undefined auStack3772 [100];
  undefined auStack3672 [1512];
  undefined auStack2160 [1040];
  undefined auStack1120 [1120];
  
  uVar18 = 0;
  __psq_st0(auStack4104,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack4104,(int)in_f31,0);
  iVar2 = FUN_802860bc();
  pfVar3 = (float *)FUN_8002e0fc(auStack3880,auStack3876);
  DAT_80340f3c = FLOAT_803de960;
  DAT_80340f38 = FLOAT_803de960;
  DAT_803408f8 = &DAT_80340f38;
  iVar14 = 1;
  pfVar5 = (float *)&DAT_80340f44;
  ppfVar17 = (float **)&DAT_803408fc;
  ppfVar6 = ppfVar17;
  iVar8 = iVar14;
  if (0 < iVar2) {
    do {
      fVar7 = *pfVar3;
      puVar9 = *(undefined4 **)((int)fVar7 + 0x54);
      iVar14 = iVar8;
      if (puVar9 != (undefined4 *)0x0) {
        if ((((*(ushort *)(puVar9 + 0x18) & 3) != 0) && (*(char *)((int)puVar9 + 0x62) != '\b')) &&
           (iVar8 < 400)) {
          *ppfVar6 = pfVar5;
          (*ppfVar6)[2] = fVar7;
          (*ppfVar6)[1] = *(float *)((int)fVar7 + 0x18) - (float)puVar9[0xe];
          pfVar5 = pfVar5 + 3;
          ppfVar6 = ppfVar6 + 1;
          iVar14 = iVar8 + 1;
          *(&DAT_803408f8)[iVar8] = *(float *)((int)fVar7 + 0x18) + (float)puVar9[0xe];
        }
        *(ushort *)(puVar9 + 0x18) = *(ushort *)(puVar9 + 0x18) & 0xfff7;
        *(undefined *)((int)puVar9 + 0xad) = 0;
        *(undefined *)(puVar9 + 0x2b) = 0xff;
        *puVar9 = 0;
        iVar8 = *(int *)((int)fVar7 + 200);
        if ((iVar8 != 0) && (*(short *)(iVar8 + 0x44) == 0x2d)) {
          puVar9 = *(undefined4 **)(iVar8 + 0x54);
          *(ushort *)(puVar9 + 0x18) = *(ushort *)(puVar9 + 0x18) & 0xfff7;
          *(undefined *)((int)puVar9 + 0xad) = 0;
          *(undefined *)(puVar9 + 0x2b) = 0xff;
          *puVar9 = 0;
        }
      }
      pfVar3 = pfVar3 + 1;
      iVar2 = iVar2 + -1;
      iVar8 = iVar14;
    } while (iVar2 != 0);
  }
  FUN_800322e8(&DAT_803408f8,iVar14);
  iVar8 = 1;
  iVar2 = 1;
  ppfVar6 = ppfVar17;
  do {
    if (iVar14 <= iVar2) {
      ppfVar6 = ppfVar17;
      for (iVar8 = 1; iVar8 < iVar14; iVar8 = iVar8 + 1) {
        fVar7 = (*ppfVar6)[2];
        if (((*(ushort *)(*(int *)((int)fVar7 + 0x54) + 0x60) & 0x200) != 0) &&
           (FUN_800348b0(fVar7,fVar7), *(int *)((int)fVar7 + 200) != 0)) {
          FUN_800348b0(fVar7);
        }
        ppfVar6 = ppfVar6 + 1;
      }
      for (iVar8 = 1; iVar8 < iVar14; iVar8 = iVar8 + 1) {
        fVar7 = (*ppfVar17)[2];
        iVar2 = *(int *)((int)fVar7 + 0x54);
        *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)((int)fVar7 + 0xc);
        *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)((int)fVar7 + 0x10);
        *(undefined4 *)(iVar2 + 0x18) = *(undefined4 *)((int)fVar7 + 0x14);
        if (*(int *)((int)fVar7 + 0x30) == 0) {
          *(undefined4 *)(iVar2 + 0x1c) = *(undefined4 *)((int)fVar7 + 0xc);
          *(undefined4 *)(iVar2 + 0x20) = *(undefined4 *)((int)fVar7 + 0x10);
          *(undefined4 *)(iVar2 + 0x24) = *(undefined4 *)((int)fVar7 + 0x14);
        }
        else {
          FUN_8000e0a0((double)*(float *)(iVar2 + 0x10),(double)*(float *)(iVar2 + 0x14),
                       (double)*(float *)(iVar2 + 0x18),iVar2 + 0x1c,iVar2 + 0x20,iVar2 + 0x24);
        }
        *(undefined *)(iVar2 + 0xae) = 0;
        *(ushort *)(iVar2 + 0x60) = *(ushort *)(iVar2 + 0x60) & 0xdfff;
        if ((((*(char *)(iVar2 + 0x71) != '\0') || ((*(ushort *)(iVar2 + 0x60) & 8) != 0)) &&
            ((*(ushort *)(iVar2 + 0x60) & 0x40) == 0)) &&
           ((*(ushort *)(iVar2 + 0x60) & 0x4000) == 0)) {
          *(float *)((int)fVar7 + 0x24) =
               FLOAT_803db418 * (*(float *)((int)fVar7 + 0xc) - *(float *)((int)fVar7 + 0x80));
          *(float *)((int)fVar7 + 0x2c) =
               FLOAT_803db418 * (*(float *)((int)fVar7 + 0x14) - *(float *)((int)fVar7 + 0x88));
        }
        ppfVar17 = ppfVar17 + 1;
      }
      DAT_802cada0 = 0;
      DAT_802cada4 = 0;
      DAT_802cada8 = 0;
      DAT_802cadac = 0;
      DAT_802cadb0 = 0;
      __psq_l0(auStack4104,uVar18);
      __psq_l1(auStack4104,uVar18);
      FUN_80286108();
      return;
    }
    fVar7 = (*ppfVar6)[2];
    iVar16 = *(int *)((int)fVar7 + 0x54);
    iVar12 = *(int *)((int)fVar7 + 200);
    if ((iVar12 != 0) &&
       ((*(int *)(iVar12 + 0x54) == 0 || ((*(ushort *)(*(int *)(iVar12 + 0x54) + 0x60) & 1) == 0))))
    {
      iVar12 = 0;
    }
    if ((*(ushort *)(iVar16 + 0x60) & 4) != 0) {
      ppfVar4 = (float **)(&DAT_803408f8 + iVar8);
      for (; (**ppfVar4 < (*ppfVar6)[1] && (iVar8 < iVar14)); iVar8 = iVar8 + 1) {
        ppfVar4 = ppfVar4 + 1;
      }
      iVar10 = iVar8 << 2;
      iVar15 = iVar8;
      while (iVar15 < iVar14) {
        pfVar3 = *(float **)((int)&DAT_803408f8 + iVar10);
        if (**ppfVar6 <= pfVar3[1]) break;
        if ((*ppfVar6)[1] <= *pfVar3) {
          fVar13 = pfVar3[2];
          iVar11 = *(int *)((int)fVar13 + 0x54);
          if ((iVar2 != iVar15) && (*(float *)((int)fVar7 + 0x30) != fVar13)) {
            dVar19 = (double)(*(float *)((int)fVar7 + 0x20) - *(float *)((int)fVar13 + 0x20));
            if (dVar19 <= (double)FLOAT_803de910) {
              dVar19 = -dVar19;
            }
            if (dVar19 < (double)(*(float *)(iVar16 + 0x2c) + *(float *)(iVar11 + 0x2c))) {
              dVar19 = (double)(*(float *)((int)fVar7 + 0x1c) - *(float *)((int)fVar13 + 0x1c));
              if (dVar19 <= (double)FLOAT_803de910) {
                dVar19 = -dVar19;
              }
              if ((((dVar19 < (double)(*(float *)(iVar16 + 0x28) + *(float *)(iVar11 + 0x28))) &&
                   ((*(ushort *)(iVar16 + 0x60) & 0x40) == 0)) &&
                  ((*(ushort *)(iVar11 + 0x60) & 0x40) == 0)) &&
                 ((((*(ushort *)(iVar11 + 0x60) & 4) == 0 || (iVar15 <= iVar2)) &&
                  (((*(byte *)(*(int *)((int)fVar7 + 0x50) + 0x71) & *(byte *)(iVar11 + 0xb5)) != 0
                   && ((*(byte *)(*(int *)((int)fVar13 + 0x50) + 0x71) & *(byte *)(iVar16 + 0xb5))
                       != 0)))))) {
                if ((*(byte *)(iVar11 + 0x62) & 0x20) == 0) {
                  if ((*(byte *)(iVar16 + 0x62) & 0x20) == 0) {
                    if ((*(byte *)(iVar16 + 0x62) == 0x10) || (*(byte *)(iVar11 + 0x62) == 0x10)) {
                      if ((*(char *)(iVar16 + 0x6a) != '\0') || (*(char *)(iVar11 + 0x6a) != '\0'))
                      {
                        FUN_800325c0(fVar7,fVar13,fVar7,0,1,0xffffffff,0);
                      }
                    }
                    else if ((*(char *)(iVar16 + 0x6a) != '\0') ||
                            (*(char *)(iVar11 + 0x6a) != '\0')) {
                      FUN_80033f84(fVar7,fVar13);
                    }
                  }
                  else {
                    FUN_80034454(fVar7,fVar13,auStack3672,auStack1120,auStack2160,auStack3772,
                                 auStack3872,0);
                  }
                }
                else {
                  FUN_80034454(fVar13,fVar7,auStack3672,auStack1120,auStack2160,auStack3772,
                               auStack3872,0);
                }
              }
            }
            if (dVar19 < (double)(*(float *)(iVar16 + 0x34) + *(float *)(iVar11 + 0x34))) {
              fVar1 = *(float *)((int)fVar7 + 0x1c) - *(float *)((int)fVar13 + 0x1c);
              if (fVar1 <= FLOAT_803de910) {
                fVar1 = -fVar1;
              }
              if ((((fVar1 < *(float *)(iVar16 + 0x30) + *(float *)(iVar11 + 0x30)) &&
                   ((*(ushort *)(iVar16 + 0x60) & 0x100) == 0)) &&
                  ((*(ushort *)(iVar11 + 0x60) & 0x100) == 0)) &&
                 (((*(byte *)(iVar16 + 0xb4) & *(byte *)(iVar11 + 0xb5)) != 0 &&
                  (((*(byte *)(iVar11 + 0xb4) & 0x80) != 0 ||
                   ((*(byte *)(iVar11 + 0xb4) & *(byte *)(iVar16 + 0xb5)) != 0)))))) {
                iVar11 = *(int *)((int)fVar13 + 200);
                if ((iVar11 != 0) &&
                   ((*(int *)(iVar11 + 0x54) == 0 ||
                    ((*(ushort *)(*(int *)(iVar11 + 0x54) + 0x60) & 1) == 0)))) {
                  iVar11 = 0;
                }
                FUN_800333cc((double)FLOAT_803db414,fVar7,fVar13,iVar12,iVar11);
              }
            }
          }
          iVar15 = iVar15 + 1;
          iVar10 = iVar10 + 4;
        }
        else {
          iVar15 = iVar15 + 1;
          iVar10 = iVar10 + 4;
        }
      }
    }
    ppfVar6 = ppfVar6 + 1;
    iVar2 = iVar2 + 1;
  } while( true );
}

