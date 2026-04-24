// Function: FUN_80261498
// Entry: 80261498
// Size: 1424 bytes

int FUN_80261498(undefined4 param_1,undefined4 *param_2,code *param_3)

{
  ushort *puVar1;
  uint uVar2;
  bool bVar3;
  byte bVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  ushort uVar10;
  undefined4 uVar9;
  int iVar11;
  ushort *puVar12;
  short *psVar13;
  char *pcVar14;
  short *psVar15;
  ushort uVar16;
  short sVar17;
  uint local_40;
  uint local_3c;
  int local_38 [4];
  int local_28;
  
  bVar4 = 0;
  bVar5 = false;
  bVar3 = false;
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = 0;
  }
  iVar7 = FUN_8025edc8(param_1,local_38 + 4);
  if (-1 < iVar7) {
    iVar7 = FUN_80260cc4(local_28);
    if (iVar7 < 0) {
      iVar7 = FUN_8025ee80(local_28);
    }
    else {
      iVar7 = FUN_80260f48(local_28,&local_40);
      iVar8 = FUN_80261188(local_28,&local_3c);
      if (iVar7 + iVar8 < 2) {
        iVar11 = *(int *)(local_28 + 0x80);
        local_38[2] = iVar11 + 0x2000;
        local_38[0] = iVar11 + 0x6000;
        local_38[3] = iVar11 + 0x4000;
        local_38[1] = iVar11 + 0x8000;
        if (iVar7 + iVar8 == 1) {
          if (*(int *)(local_28 + 0x84) == 0) {
            *(int *)(local_28 + 0x84) = local_38[local_40 + 2];
            FUN_80003494(local_38[local_40 + 2],local_38[(local_40 ^ 1) + 2],0x2000);
            bVar5 = true;
          }
          else {
            *(int *)(local_28 + 0x88) = local_38[local_3c];
            FUN_80003494(local_38[local_3c],local_38[local_3c ^ 1],0x2000);
            bVar4 = 1;
          }
        }
        iVar8 = local_38[local_3c ^ 1];
        FUN_800033a8(iVar8,0,0x2000);
        iVar11 = 0x7f;
        iVar7 = 0;
        do {
          pcVar14 = (char *)(*(int *)(local_28 + 0x84) + iVar7);
          if (*pcVar14 != -1) {
            uVar10 = *(ushort *)(pcVar14 + 0x36);
            for (uVar16 = 0; (uVar10 != 0xffff && (uVar16 < *(ushort *)(pcVar14 + 0x38)));
                uVar16 = uVar16 + 1) {
              uVar2 = (uint)uVar10;
              if ((uVar2 < 5) || (*(ushort *)(local_28 + 0x10) <= uVar2)) {
LAB_8026167c:
                iVar7 = FUN_8025ee80(local_28,0xfffffffa);
                return iVar7;
              }
              iVar6 = uVar2 * 2;
              uVar10 = *(short *)(iVar8 + iVar6) + 1;
              *(ushort *)(iVar8 + iVar6) = uVar10;
              if (1 < uVar10) goto LAB_8026167c;
              uVar10 = *(ushort *)(*(int *)(local_28 + 0x88) + iVar6);
            }
            if ((uVar16 != *(ushort *)(pcVar14 + 0x38)) || (uVar10 != 0xffff)) {
              iVar7 = FUN_8025ee80(local_28,0xfffffffa);
              return iVar7;
            }
          }
          iVar7 = iVar7 + 0x40;
          iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
        psVar13 = (short *)(iVar8 + 10);
        sVar17 = 0;
        iVar7 = 10;
        for (uVar10 = 5; uVar10 < *(ushort *)(local_28 + 0x10); uVar10 = uVar10 + 1) {
          puVar12 = (ushort *)(*(int *)(local_28 + 0x88) + iVar7);
          uVar16 = *puVar12;
          if (*psVar13 == 0) {
            if (uVar16 != 0) {
              *puVar12 = 0;
              bVar3 = true;
            }
            sVar17 = sVar17 + 1;
          }
          else if (((uVar16 < 5) || (*(ushort *)(local_28 + 0x10) <= uVar16)) && (uVar16 != 0xffff))
          {
            iVar7 = FUN_8025ee80(local_28,0xfffffffa);
            return iVar7;
          }
          iVar7 = iVar7 + 2;
          psVar13 = psVar13 + 1;
        }
        psVar13 = (short *)(*(int *)(local_28 + 0x88) + 6);
        if (sVar17 != *psVar13) {
          *psVar13 = sVar17;
          bVar3 = true;
        }
        if (bVar3) {
          psVar13 = *(short **)(local_28 + 0x88);
          psVar13[1] = 0;
          psVar15 = psVar13 + 1;
          puVar12 = (ushort *)(psVar13 + 2);
          *psVar13 = 0;
          iVar7 = 0x1ff;
          do {
            *psVar13 = *psVar13 + *puVar12;
            *psVar15 = *psVar15 + ~*puVar12;
            *psVar13 = *psVar13 + puVar12[1];
            *psVar15 = *psVar15 + ~puVar12[1];
            *psVar13 = *psVar13 + puVar12[2];
            *psVar15 = *psVar15 + ~puVar12[2];
            *psVar13 = *psVar13 + puVar12[3];
            *psVar15 = *psVar15 + ~puVar12[3];
            *psVar13 = *psVar13 + puVar12[4];
            *psVar15 = *psVar15 + ~puVar12[4];
            *psVar13 = *psVar13 + puVar12[5];
            *psVar15 = *psVar15 + ~puVar12[5];
            *psVar13 = *psVar13 + puVar12[6];
            *psVar15 = *psVar15 + ~puVar12[6];
            *psVar13 = *psVar13 + puVar12[7];
            puVar1 = puVar12 + 7;
            puVar12 = puVar12 + 8;
            *psVar15 = *psVar15 + ~*puVar1;
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
          iVar7 = 6;
          do {
            *psVar13 = *psVar13 + *puVar12;
            uVar10 = *puVar12;
            puVar12 = puVar12 + 1;
            *psVar15 = *psVar15 + ~uVar10;
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
          if (*psVar13 == -1) {
            *psVar13 = 0;
          }
          if (*psVar15 == -1) {
            *psVar15 = 0;
          }
        }
        FUN_80003494(local_38[local_3c ^ 1],local_38[local_3c],0x2000);
        if (bVar5) {
          if (param_2 != (undefined4 *)0x0) {
            *param_2 = 0x2000;
          }
          iVar7 = FUN_80260a50(param_1,param_3);
        }
        else if ((bool)(bVar4 | bVar3)) {
          if (param_2 != (undefined4 *)0x0) {
            *param_2 = 0x2000;
          }
          iVar7 = FUN_80260804(param_1,*(undefined4 *)(local_28 + 0x88),param_3);
        }
        else {
          FUN_8025ee80(local_28,0);
          if (param_3 != (code *)0x0) {
            uVar9 = FUN_8024377c();
            (*param_3)(param_1,0);
            FUN_802437a4(uVar9);
          }
          iVar7 = 0;
        }
      }
      else {
        iVar7 = FUN_8025ee80(local_28,0xfffffffa);
      }
    }
  }
  return iVar7;
}

