// Function: FUN_80055d24
// Entry: 80055d24
// Size: 1912 bytes

void FUN_80055d24(void)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  char cVar5;
  uint uVar4;
  char cVar6;
  short *psVar7;
  short sVar8;
  short *psVar9;
  int *piVar10;
  int iVar11;
  int iVar12;
  byte *pbVar13;
  int iVar14;
  short sVar16;
  uint uVar15;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  int iVar20;
  int local_58;
  int local_54;
  short local_50 [40];
  
  FUN_802860bc();
  sVar16 = 0;
  local_54 = 0;
  piVar10 = &DAT_803822a0;
  do {
    if (4 < local_54) {
      iVar3 = FUN_8002e0fc(&local_54,&local_58);
      while (local_54 < local_58) {
        iVar14 = *(int *)(iVar3 + local_54 * 4);
        local_54 = local_54 + 1;
        bVar2 = false;
        if ((-1 < *(char *)(iVar14 + 0xac)) &&
           (bVar1 = *(byte *)(*(int *)(iVar14 + 0x4c) + 4), (bVar1 & 2) == 0)) {
          if ((bVar1 & 0x10) == 0) {
            if ((*(short *)(iVar14 + 0x44) < 0) || (iVar20 = FUN_800555dc(iVar14), iVar20 == 0)) {
              if ((*(char *)(iVar14 + 0xac) < 0x50) && (*(char *)(iVar14 + 0xac) != DAT_803dcec8)) {
                bVar2 = true;
              }
            }
            else {
              bVar2 = true;
            }
          }
          else if ((*(short *)(iVar14 + 0x44) < 0) || (iVar20 = FUN_800555dc(iVar14), iVar20 == 0))
          {
            if ((*(char *)(iVar14 + 0xac) < 0x50) &&
               ((&DAT_80386468)[*(char *)(iVar14 + 0xac)] == 0)) {
              bVar2 = true;
            }
          }
          else {
            bVar2 = true;
          }
        }
        if (bVar2) {
          if ((&DAT_80386468)[*(char *)(iVar14 + 0xac)] != 0) {
            uVar15 = (uint)*(short *)(iVar14 + 0xb2);
            if ((-1 < (int)uVar15) && (-1 < (int)uVar15)) {
              iVar20 = *(int *)((&DAT_80386468)[*(char *)(iVar14 + 0xac)] + 0x10);
              *(byte *)(iVar20 + ((int)uVar15 >> 3)) =
                   *(byte *)(iVar20 + ((int)uVar15 >> 3)) & ~(byte)(1 << (uVar15 & 7));
            }
          }
          if (*(short *)(iVar14 + 0x46) == 0x72) {
            sVar8 = 0;
            for (psVar9 = local_50;
                (sVar8 < sVar16 && ((int)*(char *)(iVar14 + 0xac) != (int)*psVar9));
                psVar9 = psVar9 + 1) {
              sVar8 = sVar8 + 1;
            }
          }
          FUN_8002cbc4(iVar14);
          local_54 = local_54 + -1;
          local_58 = local_58 + -1;
        }
      }
      iVar3 = FUN_800430ac(DAT_803dcec8);
      if (iVar3 == 0) {
        for (local_54 = 0; local_54 < 0x50; local_54 = local_54 + 1) {
          if (((&DAT_80386468)[local_54] != 0) &&
             (uVar15 = (**(code **)(*DAT_803dcaac + 0x5c))(), uVar15 != 0)) {
            iVar3 = 0;
            for (; uVar15 != 0; uVar15 = uVar15 >> 1) {
              if (((uVar15 & 1) != 0) && (cVar5 = FUN_800e9540(local_54,iVar3), cVar5 == -1)) {
                FUN_800553b0((&DAT_80386468)[local_54],local_54,iVar3,0);
                FUN_800e963c(local_54,iVar3);
              }
              iVar3 = iVar3 + 1;
            }
          }
        }
        for (local_54 = 0; local_54 < sVar16; local_54 = local_54 + 1) {
          iVar3 = (int)local_50[local_54];
          if ((DAT_803dcec8 == iVar3) && (iVar14 = (&DAT_80386468)[iVar3], iVar14 != 0)) {
            uVar15 = 1;
            uVar18 = 0;
            uVar4 = *(uint *)(iVar14 + 0x20);
            pbVar13 = *(byte **)(iVar14 + 0x10);
            uVar17 = uVar4 + *(int *)(&DAT_80382350 + iVar3 * 0x8c);
            for (; uVar4 < uVar17; uVar4 = uVar4 + (uint)*(byte *)(uVar4 + 2) * 4) {
              if (((uVar15 & *pbVar13) == 0) &&
                 (iVar3 = FUN_80055980(uVar4,0,(int)local_50[local_54]), iVar3 != 0)) {
                if (-1 < (int)uVar18) {
                  iVar20 = (&DAT_80386468)[local_50[local_54]];
                  iVar14 = (int)uVar18 >> 3;
                  iVar3 = *(int *)(iVar20 + 0x10);
                  bVar1 = (byte)(1 << (uVar18 & 7));
                  *(byte *)(iVar3 + iVar14) = *(byte *)(iVar3 + iVar14) & ~bVar1;
                  iVar3 = *(int *)(iVar20 + 0x10);
                  *(byte *)(iVar3 + iVar14) = *(byte *)(iVar3 + iVar14) | bVar1;
                }
                FUN_8002df90(uVar4,1,(int)local_50[local_54],uVar18,0);
              }
              uVar18 = uVar18 + 1;
              uVar19 = uVar15 & 0x7f;
              uVar15 = uVar19 << 1;
              if (uVar19 == 0) {
                while (pbVar13 = pbVar13 + 1, *pbVar13 == 0xffffffff) {
                  uVar18 = uVar18 + 8;
                  iVar3 = uVar4 + (uint)*(byte *)(uVar4 + 2) * 4;
                  iVar3 = iVar3 + (uint)*(byte *)(iVar3 + 2) * 4;
                  iVar3 = iVar3 + (uint)*(byte *)(iVar3 + 2) * 4;
                  iVar3 = iVar3 + (uint)*(byte *)(iVar3 + 2) * 4;
                  iVar3 = iVar3 + (uint)*(byte *)(iVar3 + 2) * 4;
                  iVar3 = iVar3 + (uint)*(byte *)(iVar3 + 2) * 4;
                  iVar3 = iVar3 + (uint)*(byte *)(iVar3 + 2) * 4;
                  uVar4 = iVar3 + (uint)*(byte *)(iVar3 + 2) * 4;
                }
                uVar15 = 1;
              }
            }
          }
        }
        iVar3 = FUN_80036f50(6,&local_58);
        for (local_54 = 0; local_54 < local_58; local_54 = local_54 + 1) {
          iVar14 = *(int *)(iVar3 + local_54 * 4);
          uVar15 = (uint)*(byte *)(iVar14 + 0x34);
          iVar20 = (&DAT_80386468)[uVar15];
          if (iVar20 != 0) {
            cVar5 = *(char *)(iVar14 + 0x35);
            uVar19 = 0;
            uVar18 = *(uint *)(iVar20 + 0x20);
            uVar17 = uVar18 + *(int *)(&DAT_80382350 + uVar15 * 0x8c);
            uVar4 = (**(code **)(*DAT_803dcaac + 0x5c))(uVar15);
            if (uVar4 != 0) {
              iVar12 = 0;
              for (; uVar4 != 0; uVar4 = uVar4 >> 1) {
                if (((uVar4 & 1) != 0) && (cVar6 = FUN_800e9540(uVar15,iVar12), cVar6 == -1)) {
                  FUN_800553b0(iVar20,uVar15,iVar12,iVar14);
                }
                FUN_800e963c(uVar15,iVar12);
                iVar12 = iVar12 + 1;
              }
            }
            for (; uVar18 < uVar17; uVar18 = uVar18 + (uint)*(byte *)(uVar18 + 2) * 4) {
              iVar20 = (int)uVar19 >> 3;
              if ((int)uVar19 < 0) {
                bVar2 = false;
              }
              else if (iVar20 < 0xc4) {
                bVar2 = true;
                if ((1 << (uVar19 & 7) &
                    (int)*(char *)(*(int *)((&DAT_80386468)[uVar15] + 0x10) + iVar20)) == 0) {
                  bVar2 = false;
                }
              }
              else {
                bVar2 = false;
              }
              if ((!bVar2) &&
                 (iVar12 = FUN_80055980(uVar18,(int)(char)(cVar5 + '\x01'),uVar15), iVar12 != 0)) {
                if (-1 < (int)uVar19) {
                  iVar11 = (&DAT_80386468)[uVar15];
                  iVar12 = *(int *)(iVar11 + 0x10);
                  bVar1 = (byte)(1 << (uVar19 & 7));
                  *(byte *)(iVar12 + iVar20) = *(byte *)(iVar12 + iVar20) & ~bVar1;
                  iVar12 = *(int *)(iVar11 + 0x10);
                  *(byte *)(iVar12 + iVar20) = *(byte *)(iVar12 + iVar20) | bVar1;
                }
                FUN_8002df90(uVar18,1,uVar15,uVar19,iVar14);
              }
              uVar19 = uVar19 + 1;
            }
          }
        }
      }
      FUN_80286108();
      return;
    }
    iVar3 = 0;
    psVar9 = (short *)(*piVar10 + 0x594);
    do {
      iVar14 = (int)*psVar9;
      if (((-1 < iVar14) && (iVar14 < 0x50)) && ((&DAT_80386468)[iVar14] != 0)) {
        bVar2 = false;
        psVar7 = local_50;
        iVar14 = (int)sVar16;
        if (0 < iVar14) {
          do {
            if (*psVar7 == *psVar9) {
              bVar2 = true;
              break;
            }
            psVar7 = psVar7 + 1;
            iVar14 = iVar14 + -1;
          } while (iVar14 != 0);
        }
        if (!bVar2) {
          local_50[sVar16] = *psVar9;
          sVar16 = sVar16 + 1;
        }
      }
      psVar9 = psVar9 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 3);
    piVar10 = piVar10 + 1;
    local_54 = local_54 + 1;
  } while( true );
}

