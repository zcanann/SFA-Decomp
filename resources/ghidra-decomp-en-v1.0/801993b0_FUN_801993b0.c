// Function: FUN_801993b0
// Entry: 801993b0
// Size: 3920 bytes

/* WARNING: Removing unreachable block (ram,0x80199fe8) */
/* WARNING: Removing unreachable block (ram,0x80199e5c) */
/* WARNING: Removing unreachable block (ram,0x80199f20) */
/* WARNING: Removing unreachable block (ram,0x8019a058) */
/* WARNING: Removing unreachable block (ram,0x80199864) */

void FUN_801993b0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  byte bVar1;
  undefined2 uVar2;
  ushort uVar3;
  short sVar5;
  uint uVar4;
  short *psVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  byte bVar15;
  int *piVar10;
  short *psVar11;
  undefined4 uVar12;
  int iVar13;
  undefined4 uVar14;
  int iVar16;
  byte bVar17;
  byte *pbVar18;
  char cVar19;
  byte *pbVar20;
  undefined8 uVar21;
  int local_38;
  int local_34;
  undefined4 local_30;
  uint uStack44;
  
  uVar21 = FUN_802860c8();
  psVar6 = (short *)((ulonglong)uVar21 >> 0x20);
  iVar16 = (int)uVar21;
  pbVar18 = *(byte **)(psVar6 + 0x5c);
  pbVar20 = (byte *)(*(int *)(psVar6 + 0x26) + 0x18);
  bVar17 = 0;
  do {
    cVar19 = (char)param_3;
    if (7 < bVar17) {
      if (cVar19 < '\x01') {
        if (cVar19 < '\0') {
          *pbVar18 = *pbVar18 | 2;
        }
      }
      else {
        *pbVar18 = *pbVar18 | 1;
        FUN_800200e8((int)*(short *)(pbVar18 + 0x80),1);
      }
      FUN_80286114();
      return;
    }
    if ((pbVar20[1] != 0) && ((bVar15 = *pbVar18, (bVar15 & 4) == 0 || ((*pbVar20 & 0x20) != 0)))) {
      bVar1 = *pbVar20;
      if ((bVar1 & 0x10) == 0) {
        if (cVar19 == '\x01') {
          if ((bVar1 & 1) != 0) {
            if ((bVar15 & 1) != 0) {
              bVar1 = bVar1 & 4;
joined_r0x80199488:
              if (bVar1 == 0) goto switchD_801994e0_caseD_0;
            }
            goto code_r0x801994cc;
          }
        }
        else if ((cVar19 == -1) && ((bVar1 & 2) != 0)) {
          if ((bVar15 & 2) != 0) {
            bVar1 = bVar1 & 8;
            goto joined_r0x80199488;
          }
          goto code_r0x801994cc;
        }
      }
      else if ((bVar1 & 1) == 0) {
        if (((bVar1 & 2) == 0) || (cVar19 < '\x01')) goto code_r0x801994cc;
      }
      else if (-1 < cVar19) {
code_r0x801994cc:
        switch(pbVar20[1]) {
        case 1:
          bVar15 = pbVar20[2];
          if (bVar15 == 9) {
            iVar9 = FUN_8002b9ec();
            if (iVar9 != 0) {
              FUN_80295918((double)FLOAT_803e40d8,iVar9,10);
            }
          }
          else if (bVar15 < 9) {
            if ((7 < bVar15) && (iVar9 = FUN_8002b9ec(), iVar9 != 0)) {
              FUN_80295918((double)FLOAT_803e40d8,iVar9,1);
            }
          }
          else if (bVar15 == 0xb) {
            iVar9 = FUN_8002b9ec();
            if (iVar9 != 0) {
              FUN_80295918((double)FLOAT_803e40fc,iVar9,1);
            }
          }
          else if ((bVar15 < 0xb) && (iVar9 = FUN_8002b9ec(), iVar9 != 0)) {
            FUN_80295918((double)FLOAT_803e40d8,iVar9,0xb);
          }
          break;
        case 4:
          if (cVar19 < '\0') {
            FUN_8000b824(psVar6,*(undefined2 *)(pbVar20 + 2));
          }
          else {
            FUN_8000bb18(psVar6,*(undefined2 *)(pbVar20 + 2));
          }
          break;
        case 5:
          break;
        case 6:
          (**(code **)(*DAT_803dca50 + 0x24))(pbVar20[2],pbVar20[3],0);
          break;
        case 8:
          switch(pbVar20[2]) {
          case 0:
            if (1 < pbVar20[3]) {
              pbVar20[3] = 1;
            }
            FUN_8005cef0(pbVar20[3]);
            break;
          case 1:
            if (1 < pbVar20[3]) {
              pbVar20[3] = 1;
            }
            FUN_8005ce6c(pbVar20[3]);
            break;
          case 2:
            if (1 < pbVar20[3]) {
              pbVar20[3] = 1;
            }
            FUN_8005cdf8(pbVar20[3]);
            break;
          case 3:
            if (1 < pbVar20[3]) {
              pbVar20[3] = 1;
            }
            (**(code **)(*DAT_803dca64 + 0x1c))(pbVar20[3]);
            break;
          case 4:
            (**(code **)(*DAT_803dca84 + 0xc))(pbVar20[3]);
            break;
          case 5:
            FUN_8006fc00(pbVar20[3]);
            break;
          case 6:
            if (pbVar20[3] == 0) {
              FUN_80088c94(7,0);
            }
            else {
              FUN_80088c94(7,1);
            }
            break;
          case 7:
            if (pbVar20[3] == 0) {
              FUN_8005cd24(0);
            }
            else {
              FUN_8005cd24(1);
            }
            break;
          case 8:
            if (pbVar20[3] == 0) {
              FUN_80055000();
            }
            else {
              FUN_80055038();
            }
            break;
          case 9:
            uVar4 = FUN_80089030();
            uStack44 = (uint)pbVar20[3];
            local_30 = 0x43300000;
            FUN_80088e54((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e40f0),
                         uVar4 ^ 1);
            break;
          case 10:
            uStack44 = (uint)pbVar20[3];
            local_30 = 0x43300000;
            FUN_80088e54((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e40f0),0)
            ;
            break;
          case 0xb:
            uStack44 = (uint)pbVar20[3];
            local_30 = 0x43300000;
            FUN_80088e54((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e40f0),1)
            ;
          }
          break;
        case 10:
          FUN_80008cbc(psVar6,iVar16,*(undefined2 *)(pbVar20 + 2),param_4);
          FUN_8007d6dc(s_Trigger___d___Environment_Effect_80322548,(int)psVar6[0x22],
                       *(undefined2 *)(pbVar20 + 2),param_4);
          break;
        case 0xb:
          bVar15 = pbVar20[2];
          if (bVar15 == 2) {
            (**(code **)(*DAT_803dca54 + 0xc))(pbVar20[3],0);
          }
          else if (bVar15 < 2) {
            if (bVar15 == 0) {
LAB_80199870:
              iVar9 = FUN_80036e58(0xf,psVar6,0);
              if (iVar9 != 0) {
                (**(code **)(*DAT_803dca54 + 0x48))(pbVar20[3],iVar9,0xffffffff);
              }
            }
            else {
              (**(code **)(*DAT_803dca54 + 0xc))(pbVar20[3],1);
            }
          }
          else if (bVar15 < 4) goto LAB_80199870;
          break;
        case 0xc:
          uVar3 = *(ushort *)(pbVar20 + 2);
          iVar9 = FUN_8002e0fc(&local_38,&local_34);
          for (; local_38 < local_34; local_38 = local_38 + 1) {
            iVar13 = *(int *)(iVar9 + local_38 * 4);
            psVar11 = *(short **)(iVar13 + 0x4c);
            if (psVar11 == (short *)0x0) goto LAB_80199974;
            sVar5 = *psVar11;
            if (sVar5 == 0x54) {
LAB_80199958:
              if ((int)psVar11[0x1c] == (uint)uVar3) {
                FUN_801993b0(iVar13,iVar16,param_3,param_4);
              }
            }
            else if (sVar5 < 0x54) {
              if ((sVar5 < 0x51) && (0x4a < sVar5)) goto LAB_80199958;
            }
            else if (sVar5 == 0x230) goto LAB_80199958;
LAB_80199974:
          }
          break;
        case 0xd:
          FUN_800066e0(psVar6,iVar16,*(undefined2 *)(pbVar20 + 2),param_3,param_4,0);
          break;
        case 0x10:
          uVar12 = FUN_8002b9ec();
          FUN_8002b884(uVar12,pbVar20[2]);
          break;
        case 0x11:
          FUN_800200e8(0x4e3,*(undefined2 *)(pbVar20 + 2));
          break;
        case 0x12:
          bVar15 = pbVar20[2];
          uVar8 = (uint)bVar15 << 8 & 0x3f00 | (uint)pbVar20[3];
          uVar7 = FUN_8001ffb4(uVar8);
          uVar4 = ((uint)bVar15 << 8) >> 0xe;
          if (uVar4 == 0) {
            uVar7 = 0;
          }
          else if (uVar4 == 1) {
            uVar7 = 0xffffffff;
          }
          else if (uVar4 == 2) {
            uVar7 = ~uVar7;
          }
          FUN_800200e8(uVar8,uVar7);
          break;
        case 0x13:
          (**(code **)(*DAT_803dcaac + 0x50))
                    ((int)*(char *)(psVar6 + 0x56),*(undefined2 *)(pbVar20 + 2),1);
          break;
        case 0x14:
          (**(code **)(*DAT_803dcaac + 0x50))
                    ((int)*(char *)(psVar6 + 0x56),*(undefined2 *)(pbVar20 + 2),0);
          break;
        case 0x15:
          piVar10 = (int *)FUN_8002e07c(*(ushort *)(pbVar20 + 2) + 2);
          if (piVar10 != (int *)0x0) {
            for (; *piVar10 != -1; piVar10 = piVar10 + 1) {
              iVar9 = FUN_80053ee0();
              if (iVar9 == 0) {
                FUN_8001f7ac(0x32,3,0,*piVar10,0,0,0,0);
              }
            }
          }
          break;
        case 0x16:
          piVar10 = (int *)FUN_8002e07c(*(ushort *)(pbVar20 + 2) + 2);
          if (piVar10 != (int *)0x0) {
            for (; *piVar10 != -1; piVar10 = piVar10 + 1) {
              iVar9 = FUN_80053ee0();
              if (iVar9 != 0) {
                FUN_80054308();
              }
            }
          }
          break;
        case 0x18:
          (**(code **)(*DAT_803dcaac + 0x44))
                    ((int)*(char *)(psVar6 + 0x56),*(undefined2 *)(pbVar20 + 2));
          break;
        case 0x1a:
          (**(code **)(*DAT_803dcaac + 0x50))(pbVar20[3],pbVar20[2],1);
          break;
        case 0x1b:
          (**(code **)(*DAT_803dcaac + 0x50))(pbVar20[3],pbVar20[2],0);
          break;
        case 0x1c:
          bVar15 = pbVar20[2];
          if (bVar15 == 2) {
            uVar4 = countLeadingZeros((uint)pbVar20[3]);
            FUN_800200e8(0x3af,uVar4 >> 5);
          }
          else if (bVar15 < 2) {
            if (bVar15 == 0) {
              uVar4 = countLeadingZeros((uint)pbVar20[3]);
              FUN_800200e8(0x3ab,uVar4 >> 5);
            }
            else {
              uVar4 = countLeadingZeros((uint)pbVar20[3]);
              FUN_800200e8(0x3ac,uVar4 >> 5);
            }
          }
          else if (bVar15 < 4) {
            bVar15 = pbVar20[3];
            if (bVar15 == 1) {
              FUN_800200e8(0x3b0,0);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x134,0);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x135,0);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x142,0);
              FUN_800887cc();
            }
            else if (bVar15 == 0) {
              FUN_800200e8(0x3b0,1);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x134,0);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x135,0);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x142,0);
            }
            else if (bVar15 < 3) {
              FUN_800200e8(0x3b0,1);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x136,0);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x137,0);
              uVar12 = FUN_8002b9ec();
              uVar14 = FUN_8002b9ec();
              FUN_80008cbc(uVar14,uVar12,0x143,0);
            }
          }
          break;
        case 0x1d:
          if (pbVar20[2] == 0) {
            FUN_800200e8(0x966,1);
            FUN_800200e8(0x967,1);
            FUN_800200e8(0x968,1);
          }
          else {
            FUN_800200e8(0x966,0);
            FUN_800200e8(0x967,0);
            FUN_800200e8(0x968,0);
          }
          break;
        case 0x1e:
          (**(code **)(*DAT_803dcaac + 0x44))(pbVar20[3],pbVar20[2]);
          break;
        case 0x1f:
          psVar11 = (short *)FUN_8002b9ec();
          sVar5 = *psVar6 - *psVar11;
          if (0x8000 < sVar5) {
            sVar5 = sVar5 + 1;
          }
          if (sVar5 < -0x8000) {
            sVar5 = sVar5 + -1;
          }
          iVar9 = (int)sVar5;
          if (iVar9 < 0) {
            iVar9 = -iVar9;
          }
          if (iVar9 < 0x4001) {
            uVar12 = FUN_800571e4();
            (**(code **)(*DAT_803dcaac + 0x1c))(psVar6 + 6,(int)*psVar6,pbVar20[3],uVar12);
          }
          else {
            uVar12 = FUN_800571e4();
            (**(code **)(*DAT_803dcaac + 0x1c))
                      (psVar6 + 6,(int)(short)(*psVar6 + -0x8000),pbVar20[3],uVar12);
          }
          break;
        case 0x20:
          if (pbVar20[2] == 0) {
            FUN_80058060();
          }
          else {
            FUN_8005802c();
          }
          break;
        case 0x21:
          bVar15 = pbVar20[2];
          uVar4 = (uint)bVar15 << 8 & 0x1f00 | (uint)pbVar20[3];
          uVar8 = FUN_8001ffb4(uVar4);
          FUN_800200e8(uVar4,uVar8 ^ 1 << (((uint)bVar15 << 8) >> 0xd));
          break;
        case 0x22:
          uVar2 = *(undefined2 *)(pbVar20 + 2);
          bVar15 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(psVar6 + 0x56),uVar2);
          (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(psVar6 + 0x56),uVar2,bVar15 ^ 1);
          break;
        case 0x23:
          bVar15 = pbVar20[2];
          if (bVar15 == 2) {
            (**(code **)(*DAT_803dcaac + 0x28))();
          }
          else if (bVar15 < 2) {
            if (bVar15 == 0) {
              uVar12 = FUN_800571e4();
              (**(code **)(*DAT_803dcaac + 0x24))(psVar6 + 6,(int)*psVar6,uVar12,0);
            }
            else {
              (**(code **)(*DAT_803dcaac + 0x2c))();
            }
          }
          else if (bVar15 < 4) {
            uVar12 = FUN_800571e4();
            (**(code **)(*DAT_803dcaac + 0x24))(psVar6 + 6,(int)*psVar6,uVar12,1);
          }
          break;
        case 0x26:
          iVar9 = FUN_8002b9ac();
          if (iVar9 != 0) {
            bVar15 = pbVar20[2];
            if (bVar15 == 2) {
              iVar13 = FUN_80036e58(0x32,iVar9,0);
              if (iVar13 == 0) {
                iVar13 = FUN_80036e58(0x31,iVar9,0);
              }
              if (iVar13 != 0) {
                (**(code **)(**(int **)(iVar9 + 0x68) + 0x38))(iVar9);
              }
            }
            else if (bVar15 < 2) {
              if (bVar15 == 0) {
                (**(code **)(**(int **)(iVar9 + 0x68) + 0x3c))();
              }
              else {
                FUN_8002b9ac();
                FUN_8002cbc4();
              }
            }
            else if (bVar15 == 4) {
              FUN_800200e8(0xd00,1);
            }
            else if (bVar15 < 4) {
              FUN_800200e8(0xd00,0);
            }
          }
          break;
        case 0x27:
          uVar2 = *(undefined2 *)(pbVar20 + 2);
          FUN_80042e74(uVar2);
          FUN_80026ef4();
          FUN_8007d6dc(s___________________LOAD__d_80322588,uVar2);
          break;
        case 0x28:
          uVar2 = *(undefined2 *)(pbVar20 + 2);
          FUN_800437bc(uVar2,0x20000000);
          FUN_8007d6dc(s___________________FREE__d_803225a4,uVar2);
          break;
        case 0x2a:
          FUN_80043560(pbVar20[2],pbVar20[3]);
          FUN_8007d6dc(s___________________LEVELLOCKED_le_803225c0,pbVar20[2],pbVar20[3]);
          break;
        case 0x2b:
          FUN_8004350c(pbVar20[2],pbVar20[3],0);
          FUN_8007d6dc(s___________________LEVELUNLOCKED_l_803225f4,pbVar20[2],pbVar20[3]);
          break;
        case 0x2c:
          uStack44 = *(ushort *)(pbVar20 + 2) ^ 0x80000000;
          local_30 = 0x43300000;
          **(float **)(iVar16 + 0xb8) =
               FLOAT_803e4100 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e40d0);
          break;
        case 0x2d:
          iVar9 = FUN_8002b9ec();
          if (iVar9 == 0) {
            iVar9 = FUN_8022d768();
            if (iVar9 != 0) {
              FUN_80125ba4(*(undefined2 *)(pbVar20 + 2));
            }
          }
          else {
            (**(code **)(*DAT_803dca68 + 0x38))(*(undefined2 *)(pbVar20 + 2),0x14,0x8c,1);
          }
          break;
        case 0x2e:
          FUN_80041e3c(0);
          break;
        case 0x2f:
          iVar9 = FUN_80036e58(0x4c,psVar6,0);
          if (iVar9 != 0) {
            FUN_8023852c(iVar9,(uint)pbVar20[3] * 0x3c);
          }
        }
      }
    }
switchD_801994e0_caseD_0:
    bVar17 = bVar17 + 1;
    pbVar20 = pbVar20 + 4;
  } while( true );
}

