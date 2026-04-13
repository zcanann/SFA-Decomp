// Function: FUN_80261bfc
// Entry: 80261bfc
// Size: 1424 bytes

int FUN_80261bfc(int param_1,undefined4 *param_2,undefined *param_3)

{
  ushort *puVar1;
  uint uVar2;
  bool bVar3;
  byte bVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  ushort uVar8;
  int iVar9;
  ushort *puVar10;
  short *psVar11;
  char *pcVar12;
  short *psVar13;
  ushort uVar14;
  short sVar15;
  uint uVar16;
  uint local_40;
  uint local_3c;
  uint local_38 [4];
  int *local_28 [3];
  
  bVar4 = 0;
  bVar5 = false;
  bVar3 = false;
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = 0;
  }
  iVar6 = FUN_8025f52c(param_1,local_28);
  if (-1 < iVar6) {
    iVar6 = FUN_80261428((int)local_28[0]);
    if (iVar6 < 0) {
      iVar6 = FUN_8025f5e4(local_28[0],iVar6);
    }
    else {
      iVar6 = FUN_802616ac((int)local_28[0],&local_40);
      iVar7 = FUN_802618ec((int)local_28[0],&local_3c);
      if (iVar6 + iVar7 < 2) {
        iVar9 = local_28[0][0x20];
        local_38[2] = iVar9 + 0x2000;
        local_38[0] = iVar9 + 0x6000;
        local_38[3] = iVar9 + 0x4000;
        local_38[1] = iVar9 + 0x8000;
        if (iVar6 + iVar7 == 1) {
          if (local_28[0][0x21] == 0) {
            local_28[0][0x21] = local_38[local_40 + 2];
            FUN_80003494(local_38[local_40 + 2],local_38[(local_40 ^ 1) + 2],0x2000);
            bVar5 = true;
          }
          else {
            local_28[0][0x22] = local_38[local_3c];
            FUN_80003494(local_38[local_3c],local_38[local_3c ^ 1],0x2000);
            bVar4 = 1;
          }
        }
        uVar16 = local_38[local_3c ^ 1];
        FUN_800033a8(uVar16,0,0x2000);
        iVar7 = 0x7f;
        iVar6 = 0;
        do {
          pcVar12 = (char *)(local_28[0][0x21] + iVar6);
          if (*pcVar12 != -1) {
            uVar8 = *(ushort *)(pcVar12 + 0x36);
            for (uVar14 = 0; (uVar8 != 0xffff && (uVar14 < *(ushort *)(pcVar12 + 0x38)));
                uVar14 = uVar14 + 1) {
              uVar2 = (uint)uVar8;
              if ((uVar2 < 5) || (*(ushort *)(local_28[0] + 4) <= uVar2)) {
LAB_80261de0:
                iVar6 = FUN_8025f5e4(local_28[0],-6);
                return iVar6;
              }
              iVar9 = uVar2 * 2;
              uVar8 = *(short *)(uVar16 + iVar9) + 1;
              *(ushort *)(uVar16 + iVar9) = uVar8;
              if (1 < uVar8) goto LAB_80261de0;
              uVar8 = *(ushort *)(local_28[0][0x22] + iVar9);
            }
            if ((uVar14 != *(ushort *)(pcVar12 + 0x38)) || (uVar8 != 0xffff)) {
              iVar6 = FUN_8025f5e4(local_28[0],-6);
              return iVar6;
            }
          }
          iVar6 = iVar6 + 0x40;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
        psVar11 = (short *)(uVar16 + 10);
        sVar15 = 0;
        iVar6 = 10;
        for (uVar8 = 5; uVar8 < *(ushort *)(local_28[0] + 4); uVar8 = uVar8 + 1) {
          uVar14 = *(ushort *)(local_28[0][0x22] + iVar6);
          if (*psVar11 == 0) {
            if (uVar14 != 0) {
              *(ushort *)(local_28[0][0x22] + iVar6) = 0;
              bVar3 = true;
            }
            sVar15 = sVar15 + 1;
          }
          else if (((uVar14 < 5) || (*(ushort *)(local_28[0] + 4) <= uVar14)) && (uVar14 != 0xffff))
          {
            iVar6 = FUN_8025f5e4(local_28[0],-6);
            return iVar6;
          }
          iVar6 = iVar6 + 2;
          psVar11 = psVar11 + 1;
        }
        if (sVar15 != *(short *)(local_28[0][0x22] + 6)) {
          *(short *)(local_28[0][0x22] + 6) = sVar15;
          bVar3 = true;
        }
        if (bVar3) {
          psVar11 = (short *)local_28[0][0x22];
          psVar11[1] = 0;
          psVar13 = psVar11 + 1;
          puVar10 = (ushort *)(psVar11 + 2);
          *psVar11 = 0;
          iVar6 = 0x1ff;
          do {
            *psVar11 = *psVar11 + *puVar10;
            *psVar13 = *psVar13 + ~*puVar10;
            *psVar11 = *psVar11 + puVar10[1];
            *psVar13 = *psVar13 + ~puVar10[1];
            *psVar11 = *psVar11 + puVar10[2];
            *psVar13 = *psVar13 + ~puVar10[2];
            *psVar11 = *psVar11 + puVar10[3];
            *psVar13 = *psVar13 + ~puVar10[3];
            *psVar11 = *psVar11 + puVar10[4];
            *psVar13 = *psVar13 + ~puVar10[4];
            *psVar11 = *psVar11 + puVar10[5];
            *psVar13 = *psVar13 + ~puVar10[5];
            *psVar11 = *psVar11 + puVar10[6];
            *psVar13 = *psVar13 + ~puVar10[6];
            *psVar11 = *psVar11 + puVar10[7];
            puVar1 = puVar10 + 7;
            puVar10 = puVar10 + 8;
            *psVar13 = *psVar13 + ~*puVar1;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
          iVar6 = 6;
          do {
            *psVar11 = *psVar11 + *puVar10;
            uVar8 = *puVar10;
            puVar10 = puVar10 + 1;
            *psVar13 = *psVar13 + ~uVar8;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
          if (*psVar11 == -1) {
            *psVar11 = 0;
          }
          if (*psVar13 == -1) {
            *psVar13 = 0;
          }
        }
        FUN_80003494(local_38[local_3c ^ 1],local_38[local_3c],0x2000);
        if (bVar5) {
          if (param_2 != (undefined4 *)0x0) {
            *param_2 = 0x2000;
          }
          iVar6 = FUN_802611b4(param_1,param_3);
        }
        else if ((bool)(bVar4 | bVar3)) {
          if (param_2 != (undefined4 *)0x0) {
            *param_2 = 0x2000;
          }
          iVar6 = FUN_80260f68(param_1,(short *)local_28[0][0x22],param_3);
        }
        else {
          FUN_8025f5e4(local_28[0],0);
          if (param_3 != (undefined *)0x0) {
            FUN_80243e74();
            (*(code *)param_3)(param_1,0);
            FUN_80243e9c();
          }
          iVar6 = 0;
        }
      }
      else {
        iVar6 = FUN_8025f5e4(local_28[0],-6);
      }
    }
  }
  return iVar6;
}

