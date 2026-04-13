// Function: FUN_80055ea0
// Entry: 80055ea0
// Size: 1912 bytes

void FUN_80055ea0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  char cVar2;
  byte bVar3;
  bool bVar4;
  int iVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  short *psVar9;
  short sVar10;
  short *psVar11;
  int *piVar12;
  int iVar13;
  uint *in_r7;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar14;
  byte *pbVar15;
  uint *puVar16;
  short sVar18;
  uint uVar17;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  undefined8 uVar22;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  int local_58;
  uint local_54;
  short local_50 [40];
  
  uVar22 = FUN_80286820();
  sVar18 = 0;
  local_54 = 0;
  piVar12 = &DAT_80382f00;
  do {
    if (4 < (int)local_54) {
      iVar5 = FUN_8002e1f4(&local_54,&local_58);
      while ((int)local_54 < local_58) {
        iVar8 = *(int *)(iVar5 + local_54 * 4);
        local_54 = local_54 + 1;
        bVar4 = false;
        if ((-1 < *(char *)(iVar8 + 0xac)) &&
           (bVar1 = *(byte *)(*(int *)(iVar8 + 0x4c) + 4), (bVar1 & 2) == 0)) {
          if ((bVar1 & 0x10) == 0) {
            if ((*(short *)(iVar8 + 0x44) < 0) || (uVar17 = FUN_80055758(iVar8), uVar17 == 0)) {
              if ((*(char *)(iVar8 + 0xac) < 0x50) && (*(char *)(iVar8 + 0xac) != DAT_803ddb48)) {
                bVar4 = true;
              }
            }
            else {
              bVar4 = true;
            }
          }
          else if ((*(short *)(iVar8 + 0x44) < 0) || (uVar17 = FUN_80055758(iVar8), uVar17 == 0)) {
            if ((*(char *)(iVar8 + 0xac) < 0x50) && ((&DAT_803870c8)[*(char *)(iVar8 + 0xac)] == 0))
            {
              bVar4 = true;
            }
          }
          else {
            bVar4 = true;
          }
        }
        if (bVar4) {
          if ((&DAT_803870c8)[*(char *)(iVar8 + 0xac)] != 0) {
            uVar17 = (uint)*(short *)(iVar8 + 0xb2);
            if ((-1 < (int)uVar17) && (-1 < (int)uVar17)) {
              iVar13 = *(int *)((&DAT_803870c8)[*(char *)(iVar8 + 0xac)] + 0x10);
              *(byte *)(iVar13 + ((int)uVar17 >> 3)) =
                   *(byte *)(iVar13 + ((int)uVar17 >> 3)) & ~(byte)(1 << (uVar17 & 7));
            }
          }
          if (*(short *)(iVar8 + 0x46) == 0x72) {
            sVar10 = 0;
            for (psVar11 = local_50;
                (sVar10 < sVar18 && ((int)*(char *)(iVar8 + 0xac) != (int)*psVar11));
                psVar11 = psVar11 + 1) {
              sVar10 = sVar10 + 1;
            }
          }
          uVar22 = FUN_8002cc9c(uVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar8
                               );
          local_54 = local_54 - 1;
          local_58 = local_58 + -1;
        }
      }
      iVar5 = FUN_800431a4();
      if (iVar5 == 0) {
        for (local_54 = 0; (int)local_54 < 0x50; local_54 = local_54 + 1) {
          if (((&DAT_803870c8)[local_54] != 0) &&
             (uVar17 = (**(code **)(*DAT_803dd72c + 0x5c))(), uVar17 != 0)) {
            uVar7 = 0;
            uVar22 = extraout_f1;
            for (; uVar17 != 0; uVar17 = uVar17 >> 1) {
              if (((uVar17 & 1) != 0) && (iVar5 = FUN_800e97c4(local_54,uVar7), (char)iVar5 == -1))
              {
                FUN_8005552c(uVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             (&DAT_803870c8)[local_54],local_54,uVar7,(uint *)0x0,in_r7,in_r8,in_r9,
                             in_r10);
                uVar22 = FUN_800e98c0(local_54,uVar7);
              }
              uVar7 = uVar7 + 1;
            }
          }
        }
        for (local_54 = 0; (int)local_54 < (int)sVar18; local_54 = local_54 + 1) {
          iVar5 = (int)local_50[local_54];
          if ((DAT_803ddb48 == iVar5) && (iVar8 = (&DAT_803870c8)[iVar5], iVar8 != 0)) {
            uVar17 = 1;
            uVar20 = 0;
            uVar7 = *(uint *)(iVar8 + 0x20);
            pbVar15 = *(byte **)(iVar8 + 0x10);
            uVar19 = uVar7 + *(int *)(&DAT_80382fb0 + iVar5 * 0x8c);
            for (; uVar7 < uVar19; uVar7 = uVar7 + (uint)*(byte *)(uVar7 + 2) * 4) {
              if (((uVar17 & *pbVar15) == 0) &&
                 (iVar5 = FUN_80055afc(uVar7,0,(int)local_50[local_54]), iVar5 != 0)) {
                if (-1 < (int)uVar20) {
                  iVar13 = (&DAT_803870c8)[local_50[local_54]];
                  iVar8 = (int)uVar20 >> 3;
                  iVar5 = *(int *)(iVar13 + 0x10);
                  bVar1 = (byte)(1 << (uVar20 & 7));
                  *(byte *)(iVar5 + iVar8) = *(byte *)(iVar5 + iVar8) & ~bVar1;
                  iVar5 = *(int *)(iVar13 + 0x10);
                  *(byte *)(iVar5 + iVar8) = *(byte *)(iVar5 + iVar8) | bVar1;
                }
                in_r7 = (uint *)0x0;
                FUN_8002e088(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             uVar7,1,(char)local_50[local_54],uVar20,(uint *)0x0,in_r8,in_r9,in_r10)
                ;
              }
              uVar20 = uVar20 + 1;
              uVar21 = uVar17 & 0x7f;
              uVar17 = uVar21 << 1;
              if (uVar21 == 0) {
                while (pbVar15 = pbVar15 + 1, *pbVar15 == 0xffffffff) {
                  uVar20 = uVar20 + 8;
                  iVar5 = uVar7 + (uint)*(byte *)(uVar7 + 2) * 4;
                  iVar5 = iVar5 + (uint)*(byte *)(iVar5 + 2) * 4;
                  iVar5 = iVar5 + (uint)*(byte *)(iVar5 + 2) * 4;
                  iVar5 = iVar5 + (uint)*(byte *)(iVar5 + 2) * 4;
                  iVar5 = iVar5 + (uint)*(byte *)(iVar5 + 2) * 4;
                  iVar5 = iVar5 + (uint)*(byte *)(iVar5 + 2) * 4;
                  iVar5 = iVar5 + (uint)*(byte *)(iVar5 + 2) * 4;
                  uVar7 = iVar5 + (uint)*(byte *)(iVar5 + 2) * 4;
                }
                uVar17 = 1;
              }
            }
          }
        }
        puVar6 = FUN_80037048(6,&local_58);
        for (local_54 = 0; (int)local_54 < local_58; local_54 = local_54 + 1) {
          puVar16 = (uint *)puVar6[local_54];
          bVar1 = *(byte *)(puVar16 + 0xd);
          uVar17 = (uint)bVar1;
          iVar5 = (&DAT_803870c8)[uVar17];
          if (iVar5 != 0) {
            cVar2 = *(char *)((int)puVar16 + 0x35);
            uVar21 = 0;
            uVar20 = *(uint *)(iVar5 + 0x20);
            uVar19 = uVar20 + *(int *)(&DAT_80382fb0 + uVar17 * 0x8c);
            uVar7 = (**(code **)(*DAT_803dd72c + 0x5c))(uVar17);
            if (uVar7 != 0) {
              uVar14 = 0;
              uVar22 = extraout_f1_01;
              for (; uVar7 != 0; uVar7 = uVar7 >> 1) {
                if (((uVar7 & 1) != 0) && (iVar8 = FUN_800e97c4(uVar17,uVar14), (char)iVar8 == -1))
                {
                  FUN_8005552c(uVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,
                               uVar17,uVar14,puVar16,in_r7,in_r8,in_r9,in_r10);
                }
                uVar22 = FUN_800e98c0(uVar17,uVar14);
                uVar14 = uVar14 + 1;
              }
            }
            for (; uVar20 < uVar19; uVar20 = uVar20 + (uint)*(byte *)(uVar20 + 2) * 4) {
              iVar5 = (int)uVar21 >> 3;
              if ((int)uVar21 < 0) {
                bVar4 = false;
              }
              else if (iVar5 < 0xc4) {
                bVar4 = true;
                if ((1 << (uVar21 & 7) &
                    (int)*(char *)(*(int *)((&DAT_803870c8)[uVar17] + 0x10) + iVar5)) == 0) {
                  bVar4 = false;
                }
              }
              else {
                bVar4 = false;
              }
              if ((!bVar4) &&
                 (iVar8 = FUN_80055afc(uVar20,(int)(char)(cVar2 + '\x01'),uVar17), iVar8 != 0)) {
                if (-1 < (int)uVar21) {
                  iVar13 = (&DAT_803870c8)[uVar17];
                  iVar8 = *(int *)(iVar13 + 0x10);
                  bVar3 = (byte)(1 << (uVar21 & 7));
                  *(byte *)(iVar8 + iVar5) = *(byte *)(iVar8 + iVar5) & ~bVar3;
                  iVar8 = *(int *)(iVar13 + 0x10);
                  *(byte *)(iVar8 + iVar5) = *(byte *)(iVar8 + iVar5) | bVar3;
                }
                in_r7 = puVar16;
                FUN_8002e088(extraout_f1_02,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             uVar20,1,bVar1,uVar21,puVar16,in_r8,in_r9,in_r10);
              }
              uVar21 = uVar21 + 1;
            }
          }
        }
      }
      FUN_8028686c();
      return;
    }
    in_r8 = 0;
    psVar11 = (short *)(*piVar12 + 0x594);
    do {
      in_r7 = (uint *)(int)*psVar11;
      if (((-1 < (int)in_r7) && ((int)in_r7 < 0x50)) && ((&DAT_803870c8)[(int)in_r7] != 0)) {
        in_r9 = 0;
        psVar9 = local_50;
        iVar5 = (int)sVar18;
        if (0 < iVar5) {
          do {
            if (*psVar9 == *psVar11) {
              in_r9 = 1;
              break;
            }
            psVar9 = psVar9 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
        if ((short)in_r9 == 0) {
          local_50[sVar18] = *psVar11;
          sVar18 = sVar18 + 1;
        }
      }
      psVar11 = psVar11 + 1;
      in_r8 = in_r8 + 1;
    } while (in_r8 < 3);
    piVar12 = piVar12 + 1;
    local_54 = local_54 + 1;
  } while( true );
}

