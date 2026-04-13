// Function: FUN_8008760c
// Entry: 8008760c
// Size: 3912 bytes

/* WARNING: Removing unreachable block (ram,0x80088534) */
/* WARNING: Removing unreachable block (ram,0x8008852c) */
/* WARNING: Removing unreachable block (ram,0x80088524) */
/* WARNING: Removing unreachable block (ram,0x8008851c) */
/* WARNING: Removing unreachable block (ram,0x80087634) */
/* WARNING: Removing unreachable block (ram,0x8008762c) */
/* WARNING: Removing unreachable block (ram,0x80087624) */
/* WARNING: Removing unreachable block (ram,0x8008761c) */

void FUN_8008760c(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  char cVar2;
  byte bVar3;
  float fVar4;
  short *psVar5;
  uint uVar6;
  undefined4 uVar7;
  int iVar8;
  int *in_r7;
  int in_r8;
  int *in_r9;
  int in_r10;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  int *piVar14;
  double dVar15;
  double extraout_f1;
  double dVar16;
  double extraout_f1_00;
  double dVar17;
  double extraout_f1_01;
  undefined8 uVar18;
  undefined8 extraout_f1_02;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar19;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_98;
  float local_94;
  char *local_90;
  int local_8c;
  short *local_88 [2];
  undefined8 local_80;
  undefined8 local_78;
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
  psVar5 = (short *)FUN_80286830();
  iVar11 = 0;
  uVar12 = (uint)DAT_803dc071;
  iVar13 = *(int *)(psVar5 + 0x26);
  if (iVar13 != 0) {
    piVar14 = *(int **)(psVar5 + 0x5c);
    dVar16 = extraout_f1;
    if ((*(byte *)((int)piVar14 + 0x7f) & 2) != 0) {
      dVar16 = (double)FUN_80014b38();
    }
    local_88[0] = (short *)*piVar14;
    DAT_803ddd5a = '\0';
    DAT_803ddd94 = 0;
    DAT_803ddd92 = 0;
    DAT_803ddd91 = 0;
    if (*(char *)((int)piVar14 + 0x7e) == '\x03') {
      if (*piVar14 != 0) {
        *(short **)(local_88[0] + 0x60) = psVar5;
        local_88[0][0x58] = local_88[0][0x58] | 0x1000;
      }
    }
    else {
      iVar8 = (int)*(char *)((int)piVar14 + 0x57);
      if ((&DAT_8039a904)[iVar8] == '\x01') {
        *(undefined2 *)(piVar14 + 0x16) = *(undefined2 *)(&DAT_8039ac0c + iVar8 * 2);
        *(undefined2 *)((int)piVar14 + 0x5a) = *(undefined2 *)(piVar14 + 0x16);
        dVar16 = (double)FUN_800862e4(psVar5,local_88[0],(int)piVar14);
      }
      else {
        local_80 = (double)(longlong)(int)(float)(&DAT_8039ae0c)[iVar8];
        *(short *)(piVar14 + 0x16) = (short)(int)(float)(&DAT_8039ae0c)[iVar8];
      }
      iVar9 = 3;
      iVar8 = (int)piVar14 + 6;
      while( true ) {
        iVar10 = iVar8;
        iVar8 = iVar10 + -2;
        bVar1 = iVar9 == 0;
        iVar9 = iVar9 + -1;
        if (bVar1) break;
        if ((0 < *(short *)(iVar10 + 0x2e)) &&
           (*(ushort *)(iVar10 + 0x2e) = *(short *)(iVar10 + 0x2e) - (ushort)DAT_803dc070,
           *(short *)(iVar10 + 0x2e) < 1)) {
          *(undefined2 *)(iVar10 + 0x2e) = 0;
          dVar16 = (double)FUN_8000dbb0();
        }
      }
      (&DAT_8039b26c)[*(char *)((int)piVar14 + 0x57)] = 0;
      while( true ) {
        DAT_803ddd93 = 0;
        if (*(char *)((int)piVar14 + 0x7e) == '\0') {
          *(undefined *)(psVar5 + 0x1b) = 0;
          goto LAB_8008851c;
        }
        local_88[0] = (short *)*piVar14;
        if (local_88[0] == (short *)0x0) {
          local_88[0] = psVar5;
          if ((*(char *)((int)piVar14 + 0x7b) == '\0') && (*(char *)((int)piVar14 + 0x56) < '\x04'))
          {
            *(undefined *)((int)piVar14 + 0x56) = 0xff;
          }
        }
        else {
          *(short **)(local_88[0] + 0x60) = psVar5;
          local_88[0][0x58] = local_88[0][0x58] | 0x1000;
        }
        if (((&DAT_8039b1c4)[*(char *)((int)piVar14 + 0x57)] != '\0') &&
           ((&DAT_8039af60)[*(char *)((int)piVar14 + 0x57)] != '\0')) {
          *(short *)(piVar14 + 0x16) =
               *(short *)(piVar14 + 0x16) -
               (short)(char)(&DAT_8039af60)[*(char *)((int)piVar14 + 0x57)];
          if (*(short *)(piVar14 + 0x16) < 0) {
            *(undefined2 *)(piVar14 + 0x16) = 0;
          }
          *(short *)((int)piVar14 + 0x5a) = *(short *)(piVar14 + 0x16) + -1;
          dVar16 = (double)FUN_80086404(dVar16,param_2,param_3,param_4,param_5,param_6,param_7,
                                        param_8,psVar5,local_88[0],piVar14,(int *)0x1,in_r7,in_r8,
                                        in_r9,in_r10);
        }
        DAT_803ddd58 = 0;
        bVar1 = local_88[0] != psVar5;
        if (bVar1) {
          dVar16 = (double)FUN_8008504c((int)local_88[0],(int)psVar5,(int)piVar14);
        }
        DAT_803ddd58 = bVar1;
        if ((*(byte *)(piVar14 + 0x24) & 1) != 0) {
          (&DAT_8039b114)[*(char *)((int)piVar14 + 0x57)] = 1;
        }
        if ((*(byte *)(piVar14 + 0x24) & 2) != 0) {
          (&DAT_8039b114)[*(char *)((int)piVar14 + 0x57)] = 0;
        }
        if ((*(byte *)(piVar14 + 0x24) & 4) != 0) {
          (&DAT_8039b0bc)[*(char *)((int)piVar14 + 0x57)] = 1;
        }
        if ((*(byte *)(piVar14 + 0x24) & 8) != 0) {
          (&DAT_8039b0bc)[*(char *)((int)piVar14 + 0x57)] = 0;
        }
        if ((*(byte *)(piVar14 + 0x24) & 0x10) != 0) {
          (&DAT_8039afb8)[*(char *)((int)piVar14 + 0x57)] = 1;
        }
        if ((*(byte *)(piVar14 + 0x24) & 0x20) != 0) {
          (&DAT_8039afb8)[*(char *)((int)piVar14 + 0x57)] = 0;
        }
        if (*(char *)((int)piVar14 + 0x7e) == '\x02') break;
        cVar2 = (&DAT_8039b1c4)[*(char *)((int)piVar14 + 0x57)];
        if (cVar2 == '\x01') {
          uVar12 = 0;
        }
        else if (cVar2 == '\x02') {
          *(undefined2 *)(piVar14 + 0x16) = *(undefined2 *)(piVar14 + 0x17);
          DAT_803ddd92 = 1;
        }
        else if ((cVar2 == '\x03') && (iVar8 = FUN_80084f70(), dVar16 = extraout_f1_00, -1 < iVar8))
        {
          (&DAT_8039b26c)[*(char *)((int)piVar14 + 0x57)] = 1;
          *(short *)(piVar14 + 0x16) = (short)iVar8;
          *(undefined2 *)((int)piVar14 + 0x5a) = *(undefined2 *)(piVar14 + 0x16);
        }
        if (((*piVar14 != 0) && (*(short *)(*piVar14 + 0xb4) != -1)) &&
           (((&DAT_8039aab0)[*(char *)((int)piVar14 + 0x57)] & 0x10) == 0)) {
          dVar16 = (double)(**(code **)(*DAT_803dd6d0 + 0x5c))(0x41,1);
        }
        if ((&DAT_8039ab08)[*(char *)((int)piVar14 + 0x57)] != '\0') {
          *(undefined2 *)((int)piVar14 + 0x1a) =
               *(undefined2 *)(&DAT_8039ab60 + *(char *)((int)piVar14 + 0x57) * 2);
        }
        if (*(char *)(piVar14 + 0x1f) != 0) {
          iVar8 = FUN_80083e7c(*(char *)(piVar14 + 0x1f) + -1,(int)piVar14);
          if (iVar8 != 0) {
            local_80 = (double)CONCAT44(0x43300000,(int)*(short *)(piVar14 + 0x16) ^ 0x80000000);
            (&DAT_8039acb8)[*(char *)((int)piVar14 + 0x57)] = (float)(local_80 - DOUBLE_803dfc38);
            goto LAB_8008851c;
          }
          *(undefined *)(piVar14 + 0x1f) = 0;
        }
        *(short *)(piVar14 + 0x16) = *(short *)(piVar14 + 0x16) + (short)uVar12;
        if (*(short *)(piVar14 + 0x17) < *(short *)(piVar14 + 0x16)) {
          *(short *)(piVar14 + 0x16) = *(short *)(piVar14 + 0x17);
        }
        iVar8 = (int)*(short *)(piVar14 + 0x16);
        FUN_80086ac4(dVar16,param_2,param_3,psVar5,local_88[0],(int)piVar14,iVar8);
        *(float *)(psVar5 + 6) = *(float *)(psVar5 + 6) + (float)piVar14[1];
        *(float *)(psVar5 + 8) = *(float *)(psVar5 + 8) + (float)piVar14[2];
        *(float *)(psVar5 + 10) = *(float *)(psVar5 + 10) + (float)piVar14[3];
        psVar5[2] = psVar5[2] + *(short *)(piVar14 + 6);
        psVar5[1] = psVar5[1] + *(short *)((int)piVar14 + 0x16);
        *psVar5 = *psVar5 + *(short *)(piVar14 + 5);
        local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) + *(char *)((int)local_88[0] + 0xad) * 4);
        DAT_803ddd40 = 0;
        if (local_8c != 0) {
          if (piVar14[0x26] == 0) {
            dVar16 = (double)FLOAT_803dfc30;
          }
          else {
            dVar16 = (double)FLOAT_803dfc30;
            if ((int)*(short *)(piVar14 + 0x37) != 0) {
              dVar16 = FUN_80082e7c(dVar16,param_2,param_3,
                                    (float *)(piVar14[0x26] + *(short *)((int)piVar14 + 0xb6) * 8),
                                    (int)*(short *)(piVar14 + 0x37) & 0xfff,
                                    (int)*(short *)((int)piVar14 + 0x5a));
            }
          }
          in_f29 = (double)(float)((double)*(float *)(iVar13 + 8) + dVar16);
          if (piVar14[0x26] == 0) {
            dVar16 = (double)FLOAT_803dfc30;
          }
          else {
            dVar16 = (double)FLOAT_803dfc30;
            if ((int)*(short *)(piVar14 + 0x36) != 0) {
              dVar16 = FUN_80082e7c(dVar16,param_2,param_3,
                                    (float *)(piVar14[0x26] + *(short *)((int)piVar14 + 0xb2) * 8),
                                    (int)*(short *)(piVar14 + 0x36) & 0xfff,
                                    (int)*(short *)((int)piVar14 + 0x5a));
            }
          }
          in_f28 = (double)(float)((double)*(float *)(iVar13 + 0x10) + dVar16);
        }
        *(undefined2 *)(piVar14 + 0x16) = *(undefined2 *)((int)piVar14 + 0x5a);
        while (*(short *)(piVar14 + 0x16) < iVar8) {
          *(short *)(piVar14 + 0x16) = *(short *)(piVar14 + 0x16) + 1;
          if (piVar14[0x26] == 0) {
            dVar16 = (double)FLOAT_803dfc30;
          }
          else {
            dVar16 = (double)FLOAT_803dfc30;
            if ((int)*(short *)(piVar14 + 0x37) != 0) {
              dVar16 = FUN_80082e7c(dVar16,param_2,param_3,
                                    (float *)(piVar14[0x26] + *(short *)((int)piVar14 + 0xb6) * 8),
                                    (int)*(short *)(piVar14 + 0x37) & 0xfff,
                                    (int)*(short *)(piVar14 + 0x16));
            }
          }
          dVar16 = (double)(float)((double)*(float *)(iVar13 + 8) + dVar16);
          if (piVar14[0x26] == 0) {
            dVar17 = (double)FLOAT_803dfc30;
          }
          else {
            dVar17 = (double)FLOAT_803dfc30;
            if ((int)*(short *)(piVar14 + 0x36) != 0) {
              dVar17 = FUN_80082e7c(dVar17,param_2,param_3,
                                    (float *)(piVar14[0x26] + *(short *)((int)piVar14 + 0xb2) * 8),
                                    (int)*(short *)(piVar14 + 0x36) & 0xfff,
                                    (int)*(short *)(piVar14 + 0x16));
            }
          }
          dVar19 = (double)(float)((double)*(float *)(iVar13 + 0x10) + dVar17);
          if ((0 < *(short *)(piVar14 + 0x16)) && ((*(ushort *)((int)piVar14 + 0x6e) & 4) != 0)) {
            if ((*(char *)(piVar14 + 0x1e) == '\x01') &&
               ((*(char *)((int)piVar14 + 0x7b) == '\0' && (local_8c != 0)))) {
              dVar17 = FUN_80293900((double)((float)(dVar16 - in_f29) * (float)(dVar16 - in_f29) +
                                            (float)(dVar19 - in_f28) * (float)(dVar19 - in_f28)));
              iVar9 = FUN_8002f6cc(dVar17,(int)local_88[0],&local_94);
              if (iVar9 == 0) {
                if (piVar14[0x26] == 0) {
                  dVar17 = (double)FLOAT_803dfc30;
                }
                else {
                  dVar17 = (double)FLOAT_803dfc30;
                  if ((int)*(short *)(piVar14 + 0x35) != 0) {
                    dVar17 = FUN_80082e7c(dVar17,param_2,param_3,
                                          (float *)(piVar14[0x26] +
                                                   *(short *)((int)piVar14 + 0xae) * 8),
                                          (int)*(short *)(piVar14 + 0x35) & 0xfff,
                                          *(short *)(piVar14 + 0x16) + -1);
                  }
                }
                local_94 = (float)((double)FLOAT_803dfcb0 * dVar17);
              }
            }
            else {
              if (piVar14[0x26] == 0) {
                dVar17 = (double)FLOAT_803dfc30;
              }
              else {
                dVar17 = (double)FLOAT_803dfc30;
                if ((int)*(short *)(piVar14 + 0x35) != 0) {
                  dVar17 = FUN_80082e7c(dVar17,param_2,param_3,
                                        (float *)(piVar14[0x26] +
                                                 *(short *)((int)piVar14 + 0xae) * 8),
                                        (int)*(short *)(piVar14 + 0x35) & 0xfff,
                                        *(short *)(piVar14 + 0x16) + -1);
                }
              }
              local_94 = (float)((double)FLOAT_803dfcb0 * dVar17);
            }
            if (local_8c == 0) {
              *(float *)(local_88[0] + 0x4c) = *(float *)(local_88[0] + 0x4c) + local_94;
              fVar4 = FLOAT_803dfc48;
              while (fVar4 < *(float *)(local_88[0] + 0x4c)) {
                *(float *)(local_88[0] + 0x4c) = *(float *)(local_88[0] + 0x4c) - fVar4;
              }
              param_2 = (double)FLOAT_803dfc48;
              dVar15 = (double)FLOAT_803dfc30;
              while (dVar17 = (double)*(float *)(local_88[0] + 0x4c), dVar17 < dVar15) {
                *(float *)(local_88[0] + 0x4c) =
                     (float)((double)*(float *)(local_88[0] + 0x4c) + param_2);
              }
            }
            else {
              param_2 = (double)FLOAT_803dfc48;
              FUN_8002fb40((double)local_94,param_2);
              dVar17 = (double)FLOAT_803dfc30;
              if (dVar17 < (double)(float)piVar14[8]) {
                uVar6 = (uint)*(short *)((int)piVar14 + 0xd6);
                if (uVar6 == 0) {
                  dVar17 = (double)FLOAT_803dfcb4;
                }
                else if ((piVar14[0x26] != 0) && (uVar6 != 0)) {
                  dVar17 = FUN_80082e7c(dVar17,param_2,param_3,
                                        (float *)(piVar14[0x26] + *(short *)(piVar14 + 0x2c) * 8),
                                        uVar6 & 0xfff,*(short *)(piVar14 + 0x16) + -1);
                }
                if (dVar17 < (double)FLOAT_803dfc48) {
                  dVar17 = (double)FLOAT_803dfc48;
                }
                piVar14[8] = (int)((float)piVar14[8] - (float)((double)FLOAT_803dfc48 / dVar17));
                dVar17 = (double)(float)piVar14[8];
                if (dVar17 < (double)FLOAT_803dfc30) {
                  piVar14[8] = (int)FLOAT_803dfc30;
                }
              }
            }
          }
          in_f29 = dVar16;
          in_f28 = dVar19;
          bVar1 = false;
          while ((!bVar1 &&
                 ((int)*(short *)((int)piVar14 + 0x66) < (int)*(short *)((int)piVar14 + 0x62)))) {
            local_90 = (char *)(piVar14[0x25] + *(short *)((int)piVar14 + 0x66) * 4);
            if (*local_90 == '\0') {
              if (*(short *)(piVar14 + 0x16) < *(short *)(local_90 + 2)) {
                bVar1 = true;
              }
              else {
                *(short *)(piVar14 + 0x1a) = *(short *)(local_90 + 2);
                *(short *)((int)piVar14 + 0x66) = *(short *)((int)piVar14 + 0x66) + 1;
              }
            }
            else if (*(short *)(piVar14 + 0x16) < *(short *)(piVar14 + 0x1a)) {
              bVar1 = true;
            }
            else {
              if (*local_90 != '\x0f') {
                *(ushort *)(piVar14 + 0x1a) = *(short *)(piVar14 + 0x1a) + (ushort)(byte)local_90[1]
                ;
              }
              *(short *)((int)piVar14 + 0x66) = *(short *)((int)piVar14 + 0x66) + 1;
              in_r7 = (int *)0x0;
              iVar9 = FUN_800855e4(dVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   psVar5,local_8c,&local_90,(undefined **)0x0,0,in_r8,in_r9,in_r10)
              ;
              if (iVar9 != 0) {
                iVar8 = (int)*(short *)(piVar14 + 0x16);
              }
              local_88[0] = (short *)**(undefined4 **)(psVar5 + 0x5c);
              if ((short *)**(undefined4 **)(psVar5 + 0x5c) == (short *)0x0) {
                local_88[0] = psVar5;
              }
              local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) +
                                 *(char *)((int)local_88[0] + 0xad) * 4);
              dVar17 = extraout_f1_01;
            }
          }
        }
        iVar8 = 0;
        do {
          bVar3 = *(byte *)((int)piVar14 + iVar8 + 300);
          if (bVar3 != 0) {
            if (bVar3 == 0x13) {
              uVar6 = FUN_80014e9c(0);
              if ((uVar6 & 0x200) == 0) {
LAB_800880e8:
                uVar6 = 0;
              }
              else {
                uVar6 = 1;
              }
            }
            else if (bVar3 < 0x13) {
              if ((bVar3 < 0x12) || (uVar6 = FUN_80014e9c(0), (uVar6 & 0x100) == 0))
              goto LAB_800880e8;
              uVar6 = 1;
            }
            else if (bVar3 == 0x1a) {
              iVar9 = FUN_8012ee7c();
              uVar6 = countLeadingZeros(iVar9);
              uVar6 = uVar6 >> 5;
            }
            else {
              if ((0x19 < bVar3) || ((code *)piVar14[0x3b] == (code *)0x0)) goto LAB_800880e8;
              uVar6 = (*(code *)piVar14[0x3b])(piVar14[0x44],psVar5);
            }
            if (uVar6 != 0) {
              (&DAT_8039b26c)[*(char *)((int)piVar14 + 0x57)] = 1;
              *(undefined2 *)(piVar14 + 0x16) = *(undefined2 *)((int)piVar14 + iVar8 * 2 + 0x118);
              *(undefined2 *)((int)piVar14 + 0x5a) = *(undefined2 *)(piVar14 + 0x16);
              *(undefined *)(piVar14 + 0x4b) = 0;
              *(undefined *)((int)piVar14 + 0x12d) = 0;
              *(undefined *)((int)piVar14 + 0x12e) = 0;
              *(undefined *)((int)piVar14 + 0x12f) = 0;
              *(undefined *)(piVar14 + 0x4c) = 0;
              *(undefined *)((int)piVar14 + 0x131) = 0;
              *(undefined *)((int)piVar14 + 0x132) = 0;
              *(undefined *)((int)piVar14 + 0x133) = 0;
              *(undefined *)(piVar14 + 0x4d) = 0;
              *(undefined *)((int)piVar14 + 0x135) = 0;
              break;
            }
          }
          iVar8 = iVar8 + 1;
        } while (iVar8 < 10);
        if ((DAT_803ddd58 == '\0') && (local_88[0] != psVar5)) {
          FUN_8008504c((int)local_88[0],(int)psVar5,(int)piVar14);
        }
        bVar3 = *(byte *)(piVar14 + 0x24);
        if (bVar3 != 0) {
          bVar1 = (bVar3 & 0x40) != 0;
          if (bVar1) {
            *(byte *)(piVar14 + 0x24) = bVar3 & 0xbf;
            *(short *)(piVar14 + 0x16) = (short)piVar14[0x1d];
            *(undefined2 *)((int)piVar14 + 0x5a) = *(undefined2 *)(piVar14 + 0x16);
          }
          *(undefined *)(piVar14 + 0x24) = 0;
          (&DAT_8039b26c)[*(char *)((int)piVar14 + 0x57)] = bVar1;
        }
        *(undefined *)((int)piVar14 + 0x8b) = 0;
        *(undefined *)(piVar14 + 0x20) = 0;
        if ((local_8c != 0) && ((*(ushort *)((int)piVar14 + 0x6e) & 4) != 0)) {
          local_80 = (double)(longlong)(int)(FLOAT_803dfcd0 * (float)piVar14[8]);
          *(short *)(*(int *)(local_8c + 0x2c) + 0x58) =
               (short)(int)(FLOAT_803dfcd0 * (float)piVar14[8]);
        }
        FUN_80084c74((int)psVar5,(int)piVar14);
        if (*(char *)((int)piVar14 + 0x7a) == '\x01') {
          param_2 = (double)*(float *)(psVar5 + 8);
          param_3 = (double)*(float *)(psVar5 + 10);
          iVar8 = FUN_80065a20((double)*(float *)(psVar5 + 6),param_2,param_3,psVar5,&local_98,0);
          if (iVar8 == 0) {
            param_2 = (double)*(float *)(psVar5 + 8);
            *(float *)(psVar5 + 8) =
                 (float)(param_2 +
                        (double)((float)(param_2 - (double)local_98) - *(float *)(iVar13 + 0xc)));
          }
        }
        *psVar5 = *psVar5 + *(short *)((int)piVar14 + 0x1a);
        FUN_80087418(psVar5,local_88[0],(int)piVar14);
        uVar18 = FUN_800852ac(piVar14,local_88[0],0);
        for (iVar8 = 0; iVar8 < DAT_803ddd40; iVar8 = iVar8 + 1) {
          in_r7 = (int *)(int)(short)(&DAT_8039a0b2)[iVar8 * 4];
          in_r8 = (int)(short)(&DAT_8039a0b0)[iVar8 * 4];
          in_r9 = (int *)0x0;
          in_r10 = 0;
          iVar9 = FUN_8008399c(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar5
                               ,local_88[0],(int)piVar14,(uint *)(&DAT_8039a0ac)[iVar8 * 2],
                               (uint)in_r7,in_r8,0,0);
          if (iVar9 != 0) {
            iVar8 = DAT_803ddd40;
          }
          local_88[0] = (short *)**(undefined4 **)(psVar5 + 0x5c);
          if ((short *)**(undefined4 **)(psVar5 + 0x5c) == (short *)0x0) {
            local_88[0] = psVar5;
          }
          local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) + *(char *)((int)local_88[0] + 0xad) * 4)
          ;
          uVar18 = extraout_f1_02;
        }
        if (DAT_803ddcf0 != 0) {
          uVar7 = FUN_800804c8(DAT_803dc380);
          uVar6 = countLeadingZeros(uVar7);
          DAT_803ddcf0 = (short)(uVar6 >> 5);
        }
        *(undefined2 *)((int)piVar14 + 0x5a) = *(undefined2 *)(piVar14 + 0x16);
        if (DAT_803ddd5a == '\0') {
          if ((&DAT_8039b26c)[*(char *)((int)piVar14 + 0x57)] != '\0') {
            *(undefined2 *)(&DAT_8039ac0c + *(char *)((int)piVar14 + 0x57) * 2) =
                 *(undefined2 *)(piVar14 + 0x16);
            (&DAT_8039a904)[*(char *)((int)piVar14 + 0x57)] = 2;
            local_80 = (double)CONCAT44(0x43300000,(int)*(short *)(piVar14 + 0x16) ^ 0x80000000);
            (&DAT_8039acb8)[*(char *)((int)piVar14 + 0x57)] = (float)(local_80 - DOUBLE_803dfc38);
          }
          dVar16 = (double)FLOAT_803dfc70;
          if (dVar16 == (double)(float)(&DAT_8039acb8)[*(char *)((int)piVar14 + 0x57)]) {
            if (DAT_803dc384 == *(char *)((int)piVar14 + 0x57)) {
              iVar8 = (int)FLOAT_803ddcf4;
              local_80 = (double)(longlong)iVar8;
              FLOAT_803ddcf4 = FLOAT_803ddcf4 - FLOAT_803dfcd4;
              if ((iVar8 != (int)FLOAT_803ddcf4) &&
                 (uVar12 = uVar12 - 1, FLOAT_803ddcf4 <= FLOAT_803dfc30)) {
                DAT_803dc384 = -1;
              }
            }
            local_78 = (double)CONCAT44(0x43300000,uVar12 ^ 0x80000000);
            dVar16 = (double)(float)(local_78 - DOUBLE_803dfc38);
            (&DAT_8039acb8)[*(char *)((int)piVar14 + 0x57)] =
                 (float)(dVar16 + (double)(float)(&DAT_8039ae0c)[*(char *)((int)piVar14 + 0x57)]);
          }
        }
        else {
          local_88[0] = (short *)**(undefined4 **)(psVar5 + 0x5c);
          if ((short *)**(undefined4 **)(psVar5 + 0x5c) == (short *)0x0) {
            local_88[0] = psVar5;
          }
          local_8c = *(int *)(*(int *)(local_88[0] + 0x3e) + *(char *)((int)local_88[0] + 0xad) * 4)
          ;
          dVar16 = (double)FUN_80082d5c(psVar5,(int)local_88[0],piVar14);
        }
        if (((DAT_803ddd5a != '\0') || (*(short *)(piVar14 + 0x17) <= *(short *)(piVar14 + 0x16)))
           || (bVar1 = iVar11 == 0, iVar11 = iVar11 + -1, bVar1)) goto LAB_8008851c;
      }
      FUN_80085dc0(dVar16,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar5,local_88,
                   piVar14,iVar13,&local_8c,in_r8,in_r9,in_r10);
    }
  }
LAB_8008851c:
  FUN_8028687c();
  return;
}

