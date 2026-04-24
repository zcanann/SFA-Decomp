// Function: FUN_80087380
// Entry: 80087380
// Size: 3912 bytes

/* WARNING: Removing unreachable block (ram,0x800882a0) */
/* WARNING: Removing unreachable block (ram,0x80088290) */
/* WARNING: Removing unreachable block (ram,0x80088298) */
/* WARNING: Removing unreachable block (ram,0x800882a8) */

void FUN_80087380(void)

{
  bool bVar1;
  char cVar2;
  byte bVar3;
  ushort uVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  short *psVar8;
  undefined4 uVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  int iVar16;
  short **ppsVar17;
  undefined4 uVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double in_f28;
  double in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_98;
  float local_94;
  short *local_90;
  int local_8c;
  short *local_88 [2];
  double local_80;
  double local_78;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar18 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,SUB84(in_f28,0),0);
  psVar8 = (short *)FUN_802860cc();
  iVar14 = 0;
  uVar15 = (uint)DAT_803db411;
  iVar16 = *(int *)(psVar8 + 0x26);
  if (iVar16 == 0) {
    uVar9 = 1;
  }
  else {
    ppsVar17 = *(short ***)(psVar8 + 0x5c);
    if ((*(byte *)((int)ppsVar17 + 0x7f) & 2) != 0) {
      FUN_80014b0c();
    }
    local_88[0] = *ppsVar17;
    DAT_803dd0da = '\0';
    DAT_803dd114 = 0;
    DAT_803dd112 = 0;
    DAT_803dd111 = 0;
    if (*(char *)((int)ppsVar17 + 0x7e) == '\x03') {
      if (*ppsVar17 != (short *)0x0) {
        *(short **)(local_88[0] + 0x60) = psVar8;
        local_88[0][0x58] = local_88[0][0x58] | 0x1000;
      }
      uVar9 = 0;
    }
    else {
      iVar11 = (int)*(char *)((int)ppsVar17 + 0x57);
      if ((&DAT_80399ca4)[iVar11] == '\x01') {
        *(undefined2 *)(ppsVar17 + 0x16) = *(undefined2 *)(&DAT_80399fac + iVar11 * 2);
        *(undefined2 *)((int)ppsVar17 + 0x5a) = *(undefined2 *)(ppsVar17 + 0x16);
        FUN_80086058(psVar8,local_88[0],ppsVar17);
      }
      else {
        local_80 = (double)(longlong)(int)(float)(&DAT_8039a1ac)[iVar11];
        *(short *)(ppsVar17 + 0x16) = (short)(int)(float)(&DAT_8039a1ac)[iVar11];
      }
      iVar12 = 3;
      iVar11 = (int)ppsVar17 + 6;
      while( true ) {
        iVar13 = iVar11;
        iVar11 = iVar13 + -2;
        bVar1 = iVar12 == 0;
        iVar12 = iVar12 + -1;
        if (bVar1) break;
        if ((0 < *(short *)(iVar13 + 0x2e)) &&
           (*(ushort *)(iVar13 + 0x2e) = *(short *)(iVar13 + 0x2e) - (ushort)DAT_803db410,
           *(short *)(iVar13 + 0x2e) < 1)) {
          *(undefined2 *)(iVar13 + 0x2e) = 0;
          FUN_8000db90(psVar8,*(undefined2 *)(iVar13 + 0x36));
        }
      }
      (&DAT_8039a60c)[*(char *)((int)ppsVar17 + 0x57)] = 0;
      do {
        DAT_803dd113 = 0;
        if (*(char *)((int)ppsVar17 + 0x7e) == '\0') {
          *(undefined *)(psVar8 + 0x1b) = 0;
          uVar9 = 1;
          goto LAB_80088290;
        }
        local_88[0] = *ppsVar17;
        if (local_88[0] == (short *)0x0) {
          local_88[0] = psVar8;
          if ((*(char *)((int)ppsVar17 + 0x7b) == '\0') &&
             (*(char *)((int)ppsVar17 + 0x56) < '\x04')) {
            *(undefined *)((int)ppsVar17 + 0x56) = 0xff;
          }
        }
        else {
          *(short **)(local_88[0] + 0x60) = psVar8;
          local_88[0][0x58] = local_88[0][0x58] | 0x1000;
        }
        if (((&DAT_8039a564)[*(char *)((int)ppsVar17 + 0x57)] != '\0') &&
           ((&DAT_8039a300)[*(char *)((int)ppsVar17 + 0x57)] != '\0')) {
          *(short *)(ppsVar17 + 0x16) =
               *(short *)(ppsVar17 + 0x16) -
               (short)(char)(&DAT_8039a300)[*(char *)((int)ppsVar17 + 0x57)];
          if (*(short *)(ppsVar17 + 0x16) < 0) {
            *(undefined2 *)(ppsVar17 + 0x16) = 0;
          }
          *(short *)((int)ppsVar17 + 0x5a) = *(short *)(ppsVar17 + 0x16) + -1;
          FUN_80086178(psVar8,local_88[0],ppsVar17,1);
        }
        DAT_803dd0d8 = 0;
        bVar1 = local_88[0] != psVar8;
        if (bVar1) {
          FUN_80084dc0(local_88[0],psVar8,ppsVar17,(&DAT_8039a564)[*(char *)((int)ppsVar17 + 0x57)])
          ;
        }
        DAT_803dd0d8 = bVar1;
        if ((*(byte *)(ppsVar17 + 0x24) & 1) != 0) {
          (&DAT_8039a4b4)[*(char *)((int)ppsVar17 + 0x57)] = 1;
        }
        if ((*(byte *)(ppsVar17 + 0x24) & 2) != 0) {
          (&DAT_8039a4b4)[*(char *)((int)ppsVar17 + 0x57)] = 0;
        }
        if ((*(byte *)(ppsVar17 + 0x24) & 4) != 0) {
          (&DAT_8039a45c)[*(char *)((int)ppsVar17 + 0x57)] = 1;
        }
        if ((*(byte *)(ppsVar17 + 0x24) & 8) != 0) {
          (&DAT_8039a45c)[*(char *)((int)ppsVar17 + 0x57)] = 0;
        }
        if ((*(byte *)(ppsVar17 + 0x24) & 0x10) != 0) {
          (&DAT_8039a358)[*(char *)((int)ppsVar17 + 0x57)] = 1;
        }
        if ((*(byte *)(ppsVar17 + 0x24) & 0x20) != 0) {
          (&DAT_8039a358)[*(char *)((int)ppsVar17 + 0x57)] = 0;
        }
        if (*(char *)((int)ppsVar17 + 0x7e) == '\x02') {
          FUN_80085b34(psVar8,local_88,ppsVar17,iVar16,&local_8c);
          uVar9 = 0;
          goto LAB_80088290;
        }
        cVar2 = (&DAT_8039a564)[*(char *)((int)ppsVar17 + 0x57)];
        if (cVar2 == '\x01') {
          uVar15 = 0;
        }
        else if (cVar2 == '\x02') {
          *(undefined2 *)(ppsVar17 + 0x16) = *(undefined2 *)(ppsVar17 + 0x17);
          DAT_803dd112 = 1;
        }
        else if ((cVar2 == '\x03') && (iVar11 = FUN_80084ce4(ppsVar17,psVar8), -1 < iVar11)) {
          (&DAT_8039a60c)[*(char *)((int)ppsVar17 + 0x57)] = 1;
          *(short *)(ppsVar17 + 0x16) = (short)iVar11;
          *(undefined2 *)((int)ppsVar17 + 0x5a) = *(undefined2 *)(ppsVar17 + 0x16);
        }
        if (((*ppsVar17 != (short *)0x0) && ((*ppsVar17)[0x5a] != -1)) &&
           (((&DAT_80399e50)[*(char *)((int)ppsVar17 + 0x57)] & 0x10) == 0)) {
          (**(code **)(*DAT_803dca50 + 0x5c))(0x41,1);
        }
        if ((&DAT_80399ea8)[*(char *)((int)ppsVar17 + 0x57)] != '\0') {
          *(undefined2 *)((int)ppsVar17 + 0x1a) =
               *(undefined2 *)(&DAT_80399f00 + *(char *)((int)ppsVar17 + 0x57) * 2);
        }
        if (*(char *)(ppsVar17 + 0x1f) != 0) {
          iVar11 = FUN_80083bf0(*(char *)(ppsVar17 + 0x1f) + -1,ppsVar17,iVar16);
          if (iVar11 != 0) {
            local_80 = (double)CONCAT44(0x43300000,(int)*(short *)(ppsVar17 + 0x16) ^ 0x80000000);
            (&DAT_8039a058)[*(char *)((int)ppsVar17 + 0x57)] = (float)(local_80 - DOUBLE_803defb8);
            uVar9 = 0;
            goto LAB_80088290;
          }
          *(undefined *)(ppsVar17 + 0x1f) = 0;
        }
        *(short *)(ppsVar17 + 0x16) = *(short *)(ppsVar17 + 0x16) + (short)uVar15;
        if (*(short *)(ppsVar17 + 0x17) < *(short *)(ppsVar17 + 0x16)) {
          *(short *)(ppsVar17 + 0x16) = *(short *)(ppsVar17 + 0x17);
        }
        iVar11 = (int)*(short *)(ppsVar17 + 0x16);
        FUN_80086838(psVar8,local_88[0],ppsVar17,iVar11);
        *(float *)(psVar8 + 6) = *(float *)(psVar8 + 6) + (float)ppsVar17[1];
        *(float *)(psVar8 + 8) = *(float *)(psVar8 + 8) + (float)ppsVar17[2];
        *(float *)(psVar8 + 10) = *(float *)(psVar8 + 10) + (float)ppsVar17[3];
        psVar8[2] = psVar8[2] + *(short *)(ppsVar17 + 6);
        psVar8[1] = psVar8[1] + *(short *)((int)ppsVar17 + 0x16);
        *psVar8 = *psVar8 + *(short *)(ppsVar17 + 5);
        local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) + *(char *)((int)local_88[0] + 0xad) * 4);
        DAT_803dd0c0 = 0;
        if (local_8c != 0) {
          if (ppsVar17[0x26] == (short *)0x0) {
            dVar19 = (double)FLOAT_803defb0;
          }
          else {
            dVar19 = (double)FLOAT_803defb0;
            if (*(ushort *)(ppsVar17 + 0x37) != 0) {
              dVar19 = (double)FUN_80082bf0(ppsVar17[0x26] + *(short *)((int)ppsVar17 + 0xb6) * 4,
                                            *(ushort *)(ppsVar17 + 0x37) & 0xfff,
                                            (int)*(short *)((int)ppsVar17 + 0x5a));
            }
          }
          in_f29 = (double)(float)((double)*(float *)(iVar16 + 8) + dVar19);
          if (ppsVar17[0x26] == (short *)0x0) {
            dVar19 = (double)FLOAT_803defb0;
          }
          else {
            dVar19 = (double)FLOAT_803defb0;
            if (*(ushort *)(ppsVar17 + 0x36) != 0) {
              dVar19 = (double)FUN_80082bf0(ppsVar17[0x26] + *(short *)((int)ppsVar17 + 0xb2) * 4,
                                            *(ushort *)(ppsVar17 + 0x36) & 0xfff,
                                            (int)*(short *)((int)ppsVar17 + 0x5a));
            }
          }
          in_f28 = (double)(float)((double)*(float *)(iVar16 + 0x10) + dVar19);
        }
        *(undefined2 *)(ppsVar17 + 0x16) = *(undefined2 *)((int)ppsVar17 + 0x5a);
        while (*(short *)(ppsVar17 + 0x16) < iVar11) {
          *(short *)(ppsVar17 + 0x16) = *(short *)(ppsVar17 + 0x16) + 1;
          if (ppsVar17[0x26] == (short *)0x0) {
            dVar19 = (double)FLOAT_803defb0;
          }
          else {
            dVar19 = (double)FLOAT_803defb0;
            if (*(ushort *)(ppsVar17 + 0x37) != 0) {
              dVar19 = (double)FUN_80082bf0(ppsVar17[0x26] + *(short *)((int)ppsVar17 + 0xb6) * 4,
                                            *(ushort *)(ppsVar17 + 0x37) & 0xfff,
                                            (int)*(short *)(ppsVar17 + 0x16));
            }
          }
          dVar19 = (double)(float)((double)*(float *)(iVar16 + 8) + dVar19);
          if (ppsVar17[0x26] == (short *)0x0) {
            dVar20 = (double)FLOAT_803defb0;
          }
          else {
            dVar20 = (double)FLOAT_803defb0;
            if (*(ushort *)(ppsVar17 + 0x36) != 0) {
              dVar20 = (double)FUN_80082bf0(ppsVar17[0x26] + *(short *)((int)ppsVar17 + 0xb2) * 4,
                                            *(ushort *)(ppsVar17 + 0x36) & 0xfff,
                                            (int)*(short *)(ppsVar17 + 0x16));
            }
          }
          dVar20 = (double)(float)((double)*(float *)(iVar16 + 0x10) + dVar20);
          if ((0 < *(short *)(ppsVar17 + 0x16)) && ((*(ushort *)((int)ppsVar17 + 0x6e) & 4) != 0)) {
            if ((*(char *)(ppsVar17 + 0x1e) == '\x01') &&
               ((*(char *)((int)ppsVar17 + 0x7b) == '\0' && (local_8c != 0)))) {
              FUN_802931a0((double)((float)(dVar19 - in_f29) * (float)(dVar19 - in_f29) +
                                   (float)(dVar20 - in_f28) * (float)(dVar20 - in_f28)));
              iVar12 = FUN_8002f5d4(local_88[0],&local_94);
              if (iVar12 == 0) {
                if (ppsVar17[0x26] == (short *)0x0) {
                  dVar21 = (double)FLOAT_803defb0;
                }
                else {
                  dVar21 = (double)FLOAT_803defb0;
                  if (*(ushort *)(ppsVar17 + 0x35) != 0) {
                    dVar21 = (double)FUN_80082bf0(ppsVar17[0x26] +
                                                  *(short *)((int)ppsVar17 + 0xae) * 4,
                                                  *(ushort *)(ppsVar17 + 0x35) & 0xfff,
                                                  *(short *)(ppsVar17 + 0x16) + -1);
                  }
                }
                local_94 = (float)((double)FLOAT_803df030 * dVar21);
              }
            }
            else {
              if (ppsVar17[0x26] == (short *)0x0) {
                dVar21 = (double)FLOAT_803defb0;
              }
              else {
                dVar21 = (double)FLOAT_803defb0;
                if (*(ushort *)(ppsVar17 + 0x35) != 0) {
                  dVar21 = (double)FUN_80082bf0(ppsVar17[0x26] +
                                                *(short *)((int)ppsVar17 + 0xae) * 4,
                                                *(ushort *)(ppsVar17 + 0x35) & 0xfff,
                                                *(short *)(ppsVar17 + 0x16) + -1);
                }
              }
              local_94 = (float)((double)FLOAT_803df030 * dVar21);
            }
            if (local_8c == 0) {
              *(float *)(local_88[0] + 0x4c) = *(float *)(local_88[0] + 0x4c) + local_94;
              fVar6 = FLOAT_803defc8;
              while (fVar7 = FLOAT_803defc8, fVar5 = FLOAT_803defb0,
                    fVar6 < *(float *)(local_88[0] + 0x4c)) {
                *(float *)(local_88[0] + 0x4c) = *(float *)(local_88[0] + 0x4c) - fVar6;
              }
              while (*(float *)(local_88[0] + 0x4c) < fVar5) {
                *(float *)(local_88[0] + 0x4c) = *(float *)(local_88[0] + 0x4c) + fVar7;
              }
            }
            else {
              FUN_8002fa48((double)local_94,(double)FLOAT_803defc8,local_88[0],ppsVar17 + 0x3c);
              dVar21 = (double)FLOAT_803defb0;
              if (dVar21 < (double)(float)ppsVar17[8]) {
                uVar4 = *(ushort *)((int)ppsVar17 + 0xd6);
                if (uVar4 == 0) {
                  dVar21 = (double)FLOAT_803df034;
                }
                else if ((ppsVar17[0x26] != (short *)0x0) && (uVar4 != 0)) {
                  dVar21 = (double)FUN_80082bf0(ppsVar17[0x26] + *(short *)(ppsVar17 + 0x2c) * 4,
                                                uVar4 & 0xfff,*(short *)(ppsVar17 + 0x16) + -1);
                }
                if (dVar21 < (double)FLOAT_803defc8) {
                  dVar21 = (double)FLOAT_803defc8;
                }
                ppsVar17[8] = (short *)((float)ppsVar17[8] -
                                       (float)((double)FLOAT_803defc8 / dVar21));
                if ((float)ppsVar17[8] < FLOAT_803defb0) {
                  ppsVar17[8] = (short *)FLOAT_803defb0;
                }
              }
            }
          }
          in_f29 = dVar19;
          in_f28 = dVar20;
          bVar1 = false;
          while ((!bVar1 &&
                 ((int)*(short *)((int)ppsVar17 + 0x66) < (int)*(short *)((int)ppsVar17 + 0x62)))) {
            local_90 = ppsVar17[0x25] + *(short *)((int)ppsVar17 + 0x66) * 2;
            if (*(char *)local_90 == '\0') {
              if (*(short *)(ppsVar17 + 0x16) < local_90[1]) {
                bVar1 = true;
              }
              else {
                *(short *)(ppsVar17 + 0x1a) = local_90[1];
                *(short *)((int)ppsVar17 + 0x66) = *(short *)((int)ppsVar17 + 0x66) + 1;
              }
            }
            else if (*(short *)(ppsVar17 + 0x16) < *(short *)(ppsVar17 + 0x1a)) {
              bVar1 = true;
            }
            else {
              if (*(char *)local_90 != '\x0f') {
                *(ushort *)(ppsVar17 + 0x1a) =
                     *(short *)(ppsVar17 + 0x1a) + (ushort)*(byte *)((int)local_90 + 1);
              }
              *(short *)((int)ppsVar17 + 0x66) = *(short *)((int)ppsVar17 + 0x66) + 1;
              iVar12 = FUN_80085358(psVar8,local_8c,&local_90,0,0);
              if (iVar12 != 0) {
                iVar11 = (int)*(short *)(ppsVar17 + 0x16);
              }
              local_88[0] = **(short ***)(psVar8 + 0x5c);
              if (**(short ***)(psVar8 + 0x5c) == (short *)0x0) {
                local_88[0] = psVar8;
              }
              local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) +
                                 *(char *)((int)local_88[0] + 0xad) * 4);
            }
          }
        }
        iVar11 = 0;
        do {
          bVar3 = *(byte *)((int)ppsVar17 + iVar11 + 300);
          if (bVar3 != 0) {
            if (bVar3 == 0x13) {
              uVar10 = FUN_80014e70(0);
              if ((uVar10 & 0x200) == 0) {
LAB_80087e5c:
                uVar10 = 0;
              }
              else {
                uVar10 = 1;
              }
            }
            else if (bVar3 < 0x13) {
              if ((bVar3 < 0x12) || (uVar10 = FUN_80014e70(0), (uVar10 & 0x100) == 0))
              goto LAB_80087e5c;
              uVar10 = 1;
            }
            else if (bVar3 == 0x1a) {
              uVar9 = FUN_8012ea44();
              uVar10 = countLeadingZeros(uVar9);
              uVar10 = uVar10 >> 5;
            }
            else {
              if ((0x19 < bVar3) || (ppsVar17[0x3b] == (short *)0x0)) goto LAB_80087e5c;
              uVar10 = (*(code *)ppsVar17[0x3b])(ppsVar17[0x44],psVar8);
            }
            if (uVar10 != 0) {
              (&DAT_8039a60c)[*(char *)((int)ppsVar17 + 0x57)] = 1;
              *(undefined2 *)(ppsVar17 + 0x16) = *(undefined2 *)((int)ppsVar17 + iVar11 * 2 + 0x118)
              ;
              *(undefined2 *)((int)ppsVar17 + 0x5a) = *(undefined2 *)(ppsVar17 + 0x16);
              *(undefined *)(ppsVar17 + 0x4b) = 0;
              *(undefined *)((int)ppsVar17 + 0x12d) = 0;
              *(undefined *)((int)ppsVar17 + 0x12e) = 0;
              *(undefined *)((int)ppsVar17 + 0x12f) = 0;
              *(undefined *)(ppsVar17 + 0x4c) = 0;
              *(undefined *)((int)ppsVar17 + 0x131) = 0;
              *(undefined *)((int)ppsVar17 + 0x132) = 0;
              *(undefined *)((int)ppsVar17 + 0x133) = 0;
              *(undefined *)(ppsVar17 + 0x4d) = 0;
              *(undefined *)((int)ppsVar17 + 0x135) = 0;
              break;
            }
          }
          iVar11 = iVar11 + 1;
        } while (iVar11 < 10);
        if ((DAT_803dd0d8 == '\0') && (local_88[0] != psVar8)) {
          FUN_80084dc0(local_88[0],psVar8,ppsVar17,(&DAT_8039a564)[*(char *)((int)ppsVar17 + 0x57)])
          ;
        }
        bVar3 = *(byte *)(ppsVar17 + 0x24);
        if (bVar3 != 0) {
          bVar1 = (bVar3 & 0x40) != 0;
          if (bVar1) {
            *(byte *)(ppsVar17 + 0x24) = bVar3 & 0xbf;
            *(short *)(ppsVar17 + 0x16) = (short)ppsVar17[0x1d];
            *(undefined2 *)((int)ppsVar17 + 0x5a) = *(undefined2 *)(ppsVar17 + 0x16);
          }
          *(undefined *)(ppsVar17 + 0x24) = 0;
          (&DAT_8039a60c)[*(char *)((int)ppsVar17 + 0x57)] = bVar1;
        }
        *(undefined *)((int)ppsVar17 + 0x8b) = 0;
        *(undefined *)(ppsVar17 + 0x20) = 0;
        if ((local_8c != 0) && ((*(ushort *)((int)ppsVar17 + 0x6e) & 4) != 0)) {
          local_80 = (double)(longlong)(int)(FLOAT_803df050 * (float)ppsVar17[8]);
          *(short *)(*(int *)(local_8c + 0x2c) + 0x58) =
               (short)(int)(FLOAT_803df050 * (float)ppsVar17[8]);
        }
        FUN_800849e8(psVar8,ppsVar17);
        if ((*(char *)((int)ppsVar17 + 0x7a) == '\x01') &&
           (iVar11 = FUN_800658a4((double)*(float *)(psVar8 + 6),(double)*(float *)(psVar8 + 8),
                                  (double)*(float *)(psVar8 + 10),psVar8,&local_98,0), iVar11 == 0))
        {
          *(float *)(psVar8 + 8) =
               *(float *)(psVar8 + 8) +
               ((*(float *)(psVar8 + 8) - local_98) - *(float *)(iVar16 + 0xc));
        }
        *psVar8 = *psVar8 + *(short *)((int)ppsVar17 + 0x1a);
        FUN_8008718c(psVar8,local_88[0],ppsVar17);
        FUN_80085020(ppsVar17,local_88[0],0);
        for (iVar11 = 0; iVar11 < DAT_803dd0c0; iVar11 = iVar11 + 1) {
          iVar12 = FUN_80083710(psVar8,local_88[0],ppsVar17,(&DAT_8039944c)[iVar11 * 2],
                                (int)(short)(&DAT_80399452)[iVar11 * 4],
                                (int)(short)(&DAT_80399450)[iVar11 * 4],0,0);
          if (iVar12 != 0) {
            iVar11 = DAT_803dd0c0;
          }
          local_88[0] = **(short ***)(psVar8 + 0x5c);
          if (**(short ***)(psVar8 + 0x5c) == (short *)0x0) {
            local_88[0] = psVar8;
          }
          local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) + *(char *)((int)local_88[0] + 0xad) * 4)
          ;
        }
        if (DAT_803dd070 != 0) {
          uVar9 = FUN_8008023c(DAT_803db720);
          uVar10 = countLeadingZeros(uVar9);
          DAT_803dd070 = (short)(uVar10 >> 5);
        }
        *(undefined2 *)((int)ppsVar17 + 0x5a) = *(undefined2 *)(ppsVar17 + 0x16);
        if (DAT_803dd0da == '\0') {
          if ((&DAT_8039a60c)[*(char *)((int)ppsVar17 + 0x57)] != '\0') {
            *(undefined2 *)(&DAT_80399fac + *(char *)((int)ppsVar17 + 0x57) * 2) =
                 *(undefined2 *)(ppsVar17 + 0x16);
            (&DAT_80399ca4)[*(char *)((int)ppsVar17 + 0x57)] = 2;
            local_80 = (double)CONCAT44(0x43300000,(int)*(short *)(ppsVar17 + 0x16) ^ 0x80000000);
            (&DAT_8039a058)[*(char *)((int)ppsVar17 + 0x57)] = (float)(local_80 - DOUBLE_803defb8);
          }
          if (FLOAT_803deff0 == (float)(&DAT_8039a058)[*(char *)((int)ppsVar17 + 0x57)]) {
            if (DAT_803db724 == *(char *)((int)ppsVar17 + 0x57)) {
              iVar11 = (int)FLOAT_803dd074;
              local_80 = (double)(longlong)iVar11;
              FLOAT_803dd074 = FLOAT_803dd074 - FLOAT_803df054;
              if ((iVar11 != (int)FLOAT_803dd074) &&
                 (uVar15 = uVar15 - 1, FLOAT_803dd074 <= FLOAT_803defb0)) {
                DAT_803db724 = -1;
              }
            }
            local_78 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
            (&DAT_8039a058)[*(char *)((int)ppsVar17 + 0x57)] =
                 (float)(local_78 - DOUBLE_803defb8) +
                 (float)(&DAT_8039a1ac)[*(char *)((int)ppsVar17 + 0x57)];
          }
        }
        else {
          local_88[0] = **(short ***)(psVar8 + 0x5c);
          if (**(short ***)(psVar8 + 0x5c) == (short *)0x0) {
            local_88[0] = psVar8;
          }
          local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) + *(char *)((int)local_88[0] + 0xad) * 4)
          ;
          FUN_80082ad0(psVar8,local_88[0],ppsVar17);
        }
      } while (((DAT_803dd0da == '\0') &&
               (*(short *)(ppsVar17 + 0x16) < *(short *)(ppsVar17 + 0x17))) &&
              (bVar1 = iVar14 != 0, iVar14 = iVar14 + -1, bVar1));
      uVar9 = 0;
    }
  }
LAB_80088290:
  __psq_l0(auStack8,uVar18);
  __psq_l1(auStack8,uVar18);
  __psq_l0(auStack24,uVar18);
  __psq_l1(auStack24,uVar18);
  __psq_l0(auStack40,uVar18);
  __psq_l1(auStack40,uVar18);
  __psq_l0(auStack56,uVar18);
  __psq_l1(auStack56,uVar18);
  FUN_80286118(uVar9);
  return;
}

