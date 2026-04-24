// Function: FUN_8013b368
// Entry: 8013b368
// Size: 8744 bytes

/* WARNING: Removing unreachable block (ram,0x8013d57c) */
/* WARNING: Removing unreachable block (ram,0x8013cab4) */
/* WARNING: Removing unreachable block (ram,0x8013cacc) */
/* WARNING: Removing unreachable block (ram,0x8013d584) */

void FUN_8013b368(void)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  short sVar11;
  undefined4 uVar7;
  uint uVar8;
  uint uVar9;
  ushort uVar12;
  float *pfVar10;
  char cVar14;
  char cVar15;
  short sVar13;
  int iVar16;
  undefined *puVar17;
  byte bVar18;
  int iVar19;
  undefined2 uVar20;
  uint uVar21;
  uint unaff_r23;
  undefined4 *puVar22;
  int iVar23;
  undefined4 uVar24;
  undefined8 extraout_f1;
  double dVar25;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar26;
  undefined8 uVar27;
  byte local_a8;
  byte local_a7;
  short local_a4;
  undefined2 local_a2;
  undefined2 local_a0;
  undefined auStack156 [8];
  undefined uStack148;
  byte local_93;
  ushort local_92 [5];
  float local_88;
  float local_84;
  float local_80;
  undefined4 auStack124 [9];
  longlong local_58;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar24 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar27 = FUN_802860c4();
  psVar3 = (short *)((ulonglong)uVar27 >> 0x20);
  iVar16 = (int)uVar27;
  cVar15 = '\x01';
  uVar27 = extraout_f1;
  if ((*(byte *)(iVar16 + 9) < 5) && (iVar4 = FUN_800dbba4(psVar3 + 0xc), iVar4 == 0)) {
    (**(code **)(*DAT_803dcaa8 + 0x20))(psVar3,iVar16 + 0xf8);
    *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(iVar16 + 0xe0);
    *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(iVar16 + 0xe4);
    *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(iVar16 + 0xe8);
    *(undefined4 *)(psVar3 + 0xc) = *(undefined4 *)(iVar16 + 0xe0);
    *(undefined4 *)(psVar3 + 0xe) = *(undefined4 *)(iVar16 + 0xe4);
    *(undefined4 *)(psVar3 + 0x10) = *(undefined4 *)(iVar16 + 0xe8);
    FUN_80035f8c(psVar3);
  }
  puVar22 = *(undefined4 **)(iVar16 + 0x28);
  uVar5 = FUN_800dbcfc(psVar3 + 0xc,0);
  if ((uVar5 != 0) && (*(ushort *)(iVar16 + 0xd0) != uVar5)) {
    *(short *)(iVar16 + 0xd0) = (short)uVar5;
    *(uint *)(iVar16 + 0x54) = *(uint *)(iVar16 + 0x54) & 0xfffffbff;
    *(undefined2 *)(iVar16 + 0x98) = 0;
    *(undefined2 *)(iVar16 + 0x9a) = 0;
    *(undefined2 *)(iVar16 + 0x9c) = 0;
    *(undefined2 *)(iVar16 + 0x9e) = 0;
  }
  uVar6 = FUN_800dbcfc(puVar22,&uStack148);
  if (((uVar5 != 0) && (uVar6 == 0)) && (sVar11 = FUN_800dba4c(puVar22,uVar5), sVar11 != 0)) {
    FUN_800db224(sVar11,&local_a8);
    uVar6 = (uint)local_a8;
    if (uVar6 == uVar5) {
      uVar6 = (uint)local_a7;
    }
  }
  if ((uVar6 != 0) && (uVar6 != *(ushort *)(iVar16 + 0x532))) {
    *(short *)(iVar16 + 0x532) = (short)uVar6;
  }
  *(undefined2 *)(iVar16 + 0x534) = *(undefined2 *)(iVar16 + 0x532);
  FUN_80148bc8(s_tricky_wg__d___d_target_wg__d__d_8031d4d0,*(undefined2 *)(iVar16 + 0xd0),uVar5,
               uVar6,*(undefined2 *)(iVar16 + 0x532));
  if (*(short *)(iVar16 + 0xd0) == 0) {
    FUN_80148b78((double)*(float *)(psVar3 + 0xc),(double)*(float *)(psVar3 + 0xe),
                 (double)*(float *)(psVar3 + 0x10),s_tricky_last_walk_group_is_zero__H_8031d4fc);
  }
  dVar26 = (double)*(float *)(iVar16 + 0x14);
  FUN_8013d5a4(uVar27,psVar3,iVar16,puVar22,0);
  FUN_80148bc8(dVar26,(double)*(float *)(iVar16 + 0x14),s_velbefore__f__vel_now__f_8031d550);
  if (uVar6 == *(ushort *)(iVar16 + 0xd0)) {
    *(uint *)(iVar16 + 0x54) = *(uint *)(iVar16 + 0x54) | 0x400;
    uVar21 = 1;
    puVar17 = &uStack148;
    iVar23 = 2;
    iVar4 = iVar16;
    iVar19 = iVar16;
    do {
      if ((uVar21 & local_93) != 0) {
        *(undefined2 *)(iVar4 + 0x98) = *(undefined2 *)(puVar17 + 2);
        *(undefined4 *)(iVar19 + 0xa0) = *puVar22;
        *(undefined4 *)(iVar19 + 0xa4) = puVar22[1];
        *(undefined4 *)(iVar19 + 0xa8) = puVar22[2];
      }
      if ((uVar21 << 1 & (uint)local_93) != 0) {
        *(undefined2 *)(iVar4 + 0x9a) = *(undefined2 *)(puVar17 + 4);
        *(undefined4 *)(iVar19 + 0xac) = *puVar22;
        *(undefined4 *)(iVar19 + 0xb0) = puVar22[1];
        *(undefined4 *)(iVar19 + 0xb4) = puVar22[2];
      }
      puVar17 = puVar17 + 4;
      iVar4 = iVar4 + 4;
      iVar19 = iVar19 + 0x18;
      uVar21 = (uVar21 & 0x3f) << 2;
      iVar23 = iVar23 + -1;
    } while (iVar23 != 0);
  }
  if ((uVar6 == 0) || (uVar6 != *(ushort *)(iVar16 + 0xd0))) {
    uVar21 = uVar6 * *(ushort *)(iVar16 + 0xd0) & 0xffff;
    if (uVar21 != 0) {
      uVar20 = (undefined2)uVar21;
      if ((uVar21 == local_92[0]) && ((local_93 & 1) != 0)) {
        *(undefined2 *)(iVar16 + 0xd2) = uVar20;
        *(undefined4 *)(iVar16 + 0xd4) = *puVar22;
        *(undefined4 *)(iVar16 + 0xd8) = puVar22[1];
        *(undefined4 *)(iVar16 + 0xdc) = puVar22[2];
      }
      if ((uVar21 == local_92[1]) && ((local_93 & 2) != 0)) {
        *(undefined2 *)(iVar16 + 0xd2) = uVar20;
        *(undefined4 *)(iVar16 + 0xd4) = *puVar22;
        *(undefined4 *)(iVar16 + 0xd8) = puVar22[1];
        *(undefined4 *)(iVar16 + 0xdc) = puVar22[2];
      }
      if ((uVar21 == local_92[2]) && ((local_93 & 4) != 0)) {
        *(undefined2 *)(iVar16 + 0xd2) = uVar20;
        *(undefined4 *)(iVar16 + 0xd4) = *puVar22;
        *(undefined4 *)(iVar16 + 0xd8) = puVar22[1];
        *(undefined4 *)(iVar16 + 0xdc) = puVar22[2];
      }
      if ((uVar21 == local_92[3]) && ((local_93 & 8) != 0)) {
        *(undefined2 *)(iVar16 + 0xd2) = uVar20;
        *(undefined4 *)(iVar16 + 0xd4) = *puVar22;
        *(undefined4 *)(iVar16 + 0xd8) = puVar22[1];
        *(undefined4 *)(iVar16 + 0xdc) = puVar22[2];
      }
    }
  }
  else {
    *(undefined2 *)(iVar16 + 0xd2) = 0;
  }
  iVar4 = FUN_800dbba4(puVar22);
  if (iVar4 == 0) {
    FUN_80148bc8(s_target_is_not_within_a_walkGroup_8031d598);
  }
  else {
    FUN_80148bc8(s_target_is_within_a_walkGroup_or_i_8031d56c);
  }
  uVar7 = FUN_800dba4c(puVar22,*(undefined2 *)(iVar16 + 0xd0));
  FUN_80148bc8(s_target_is_within_patch_group__d_8031d5cc,uVar7);
  if ((*(uint *)(iVar16 + 0x54) & 0x400) != 0) {
    iVar23 = 0;
    iVar4 = iVar16;
    iVar19 = iVar16;
    do {
      if (*(short *)(iVar19 + 0x98) != 0) {
        FUN_80148bc8((double)*(float *)(iVar4 + 0xa0),(double)*(float *)(iVar4 + 0xa4),
                     (double)*(float *)(iVar4 + 0xa8),s_Patch__d__Last_xyz__f__f__f_8031d5f0,iVar23)
        ;
      }
      iVar19 = iVar19 + 2;
      iVar4 = iVar4 + 0xc;
      iVar23 = iVar23 + 1;
    } while (iVar23 < 4);
  }
  if (*(short *)(iVar16 + 0xd2) != 0) {
    FUN_80148bc8((double)*(float *)(iVar16 + 0xd4),(double)*(float *)(iVar16 + 0xd8),
                 (double)*(float *)(iVar16 + 0xdc),s_Last_Patch_Point__f__f__f_8031d610);
  }
  uVar8 = FUN_800dba4c(puVar22,*(undefined2 *)(iVar16 + 0xd0));
  uVar21 = uVar8 & 0xffff;
  uVar9 = FUN_800dba4c(psVar3 + 0xc,*(undefined2 *)(iVar16 + 0xd0));
  uVar9 = uVar9 & 0xffff;
  if ((uVar6 == 0) || (uVar5 != uVar6)) {
    sVar11 = FUN_800db3e4(psVar3 + 0xc,puVar22,*(undefined2 *)(iVar16 + 0xd0));
    if (sVar11 == 0) {
      if (*(byte *)(iVar16 + 9) < 5) {
        if (uVar21 == 0) {
          if (uVar6 == 0) {
            if (uVar5 == 0) {
              *(undefined *)(iVar16 + 9) = 0;
            }
            else {
              uVar12 = FUN_800dbecc(puVar22);
              if (uVar12 == 0) {
                *(undefined *)(iVar16 + 9) = 0;
              }
              else {
                *(ushort *)(iVar16 + 0x532) = uVar12 & 0xff;
                *(undefined *)(iVar16 + 9) = 5;
              }
            }
          }
          else if (uVar5 == 0) {
            uVar21 = FUN_800dba4c(psVar3 + 0xc,*(undefined2 *)(iVar16 + 0xd0));
            uVar21 = uVar21 & 0xffff;
            if (uVar21 == 0) {
              FUN_80148b78(s_tricky_error_2______8031d6d4);
              *(undefined *)(iVar16 + 9) = 0;
            }
            else if (uVar6 == *(ushort *)(iVar16 + 0xd0)) {
              uVar6 = 0;
              iVar19 = 4;
              iVar4 = iVar16;
              do {
                if ((int)*(short *)(iVar4 + 0x98) == uVar21) {
                  unaff_r23 = uVar6 & 0xff;
                  *(undefined *)(iVar16 + 9) = 2;
                  break;
                }
                iVar4 = iVar4 + 2;
                uVar6 = uVar6 + 1;
                iVar19 = iVar19 + -1;
              } while (iVar19 != 0);
              if (uVar6 == 4) {
                FUN_800db240(puVar22,iVar16 + 0xec);
                *(undefined *)(iVar16 + 9) = 4;
              }
            }
            else if ((int)*(short *)(iVar16 + 0xd2) == uVar21) {
              *(undefined *)(iVar16 + 9) = 3;
            }
            else {
              FUN_800db240(puVar22,iVar16 + 0xec);
              *(undefined *)(iVar16 + 9) = 4;
            }
          }
          else {
            uVar6 = uVar6 * uVar5 & 0xffff;
            iVar4 = FUN_800db8d8(psVar3 + 0xc,*(undefined2 *)(iVar16 + 0xd0),uVar6);
            if (iVar4 == 0) {
              uVar21 = 0;
              iVar19 = 4;
              iVar4 = iVar16;
              do {
                if ((int)*(short *)(iVar4 + 0x98) == uVar6) {
                  unaff_r23 = uVar21 & 0xff;
                  *(undefined *)(iVar16 + 9) = 2;
                  break;
                }
                iVar4 = iVar4 + 2;
                uVar21 = uVar21 + 1;
                iVar19 = iVar19 + -1;
              } while (iVar19 != 0);
              if ((uVar21 == 4) || (uVar6 != (int)*(short *)(iVar16 + 0xd2))) {
                *(undefined *)(iVar16 + 9) = 5;
              }
            }
            else if ((int)*(short *)(iVar16 + 0xd2) == uVar6) {
              *(undefined *)(iVar16 + 9) = 3;
            }
            else {
              *(undefined *)(iVar16 + 9) = 5;
            }
          }
        }
        else if (uVar6 == 0) {
          if (uVar5 == 0) {
            if (uVar9 == 0) {
              FUN_80148b78(s_Tricky_is_neither_in_a_walkgroup_8031d62c);
              *(undefined *)(iVar16 + 9) = 0;
            }
            else {
              uVar6 = 0;
              iVar19 = 4;
              iVar4 = iVar16;
              do {
                if ((int)*(short *)(iVar4 + 0x98) == uVar9) {
                  uVar9 = uVar6 & 0xffff;
                  *(undefined *)(iVar16 + 9) = 2;
                  break;
                }
                iVar4 = iVar4 + 2;
                uVar6 = uVar6 + 1;
                iVar19 = iVar19 + -1;
              } while (iVar19 != 0);
              if (uVar6 == 4) {
                FUN_800db240(puVar22,iVar16 + 0xec,uVar9);
                *(undefined *)(iVar16 + 9) = 4;
              }
            }
          }
          else {
            uVar6 = 0;
            iVar19 = 4;
            iVar4 = iVar16;
            do {
              if ((int)*(short *)(iVar4 + 0x98) == uVar21) {
                unaff_r23 = uVar6 & 0xff;
                *(undefined *)(iVar16 + 9) = 2;
                break;
              }
              iVar4 = iVar4 + 2;
              uVar6 = uVar6 + 1;
              iVar19 = iVar19 + -1;
            } while (iVar19 != 0);
            if (uVar6 == 4) {
              uVar6 = countLeadingZeros(0xff - (uint)*(ushort *)(iVar16 + 0x530));
              if ((uVar21 & uVar6 >> 5) == 0) {
                *(ushort *)(iVar16 + 0x532) = (ushort)uVar21 & 0xff;
              }
              else {
                *(ushort *)(iVar16 + 0x532) = (ushort)(uVar8 >> 8) & 0xff;
              }
              *(undefined *)(iVar16 + 9) = 5;
            }
          }
        }
        else if (uVar5 == 0) {
          if (uVar5 == 0) {
            uVar21 = FUN_800dba4c(psVar3 + 0xc,*(undefined2 *)(iVar16 + 0xd0));
            uVar21 = uVar21 & 0xffff;
            if (uVar21 != 0) {
              if ((int)*(short *)(iVar16 + 0xd2) == uVar21) {
                *(undefined *)(iVar16 + 9) = 3;
              }
              else {
                FUN_800db240(puVar22,iVar16 + 0xec,uVar21);
                *(undefined *)(iVar16 + 9) = 4;
              }
              goto LAB_8013bc70;
            }
          }
          uVar7 = FUN_800db8d8(psVar3 + 0xc,*(undefined2 *)(iVar16 + 0xd0),uVar21);
          FUN_80148b78(s_tricky_error__target_patch__d__t_8031d65c,uVar21,uVar6,0,
                       *(undefined2 *)(iVar16 + 0xd0),uVar7);
          *(undefined *)(iVar16 + 9) = 0;
        }
        else {
          uVar6 = 0;
          iVar19 = 4;
          iVar4 = iVar16;
          do {
            if ((int)*(short *)(iVar4 + 0x98) == uVar21) {
              unaff_r23 = uVar6 & 0xff;
              *(undefined *)(iVar16 + 9) = 2;
              break;
            }
            iVar4 = iVar4 + 2;
            uVar6 = uVar6 + 1;
            iVar19 = iVar19 + -1;
          } while (iVar19 != 0);
          if (uVar6 == 4) {
            *(undefined *)(iVar16 + 9) = 5;
          }
        }
      }
    }
    else {
      *(undefined *)(iVar16 + 9) = 1;
      if (sVar11 != *(short *)(iVar16 + 0xd0)) {
        *(short *)(iVar16 + 0xd0) = sVar11;
        *(uint *)(iVar16 + 0x54) = *(uint *)(iVar16 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar16 + 0x98) = 0;
        *(undefined2 *)(iVar16 + 0x9a) = 0;
        *(undefined2 *)(iVar16 + 0x9c) = 0;
        *(undefined2 *)(iVar16 + 0x9e) = 0;
      }
    }
  }
  else {
    *(undefined *)(iVar16 + 9) = 1;
  }
LAB_8013bc70:
  if (*(byte *)(iVar16 + 9) < 5) {
    *(uint *)(iVar16 + 0x54) = *(uint *)(iVar16 + 0x54) & 0xffffdfff;
  }
  FUN_80148bc8(s_movement_state_is__d_8031d6ec,*(undefined *)(iVar16 + 9));
  switch(*(undefined *)(iVar16 + 9)) {
  case 0:
    FUN_80148bc8(s_walk_wait_8031d704);
    fVar1 = (float)((double)FLOAT_803e241c * (double)FLOAT_803db414 + dVar26);
    if (fVar1 < FLOAT_803e23dc) {
      fVar1 = FLOAT_803e23dc;
    }
    *(float *)(iVar16 + 0x14) = fVar1;
    if (FLOAT_803e23dc == *(float *)(iVar16 + 0x14)) {
      cVar15 = '\0';
    }
    else {
      cVar15 = FUN_80139a8c(psVar3,puVar22);
    }
    break;
  case 1:
    FUN_80148bc8(s_walk_free_8031d710);
    cVar15 = FUN_80139a8c(psVar3,puVar22);
    break;
  case 2:
    FUN_80148bc8(s_walk_start_patch_8031d71c);
    *(float *)(iVar16 + 0x14) = (float)dVar26;
    iVar4 = iVar16 + (unaff_r23 & 0xff) * 0xc + 0xa0;
    FUN_8013d5a4((double)FLOAT_803e23dc,psVar3,iVar16,iVar4,1);
    cVar15 = FUN_80139a8c(psVar3,iVar4);
    break;
  case 3:
    FUN_80148bc8(s_walk_end_patch_8031d744);
    *(float *)(iVar16 + 0x14) = (float)dVar26;
    FUN_8013d5a4((double)FLOAT_803e2488,psVar3,iVar16,iVar16 + 0xd4,1);
    cVar15 = FUN_80139a8c(psVar3,iVar16 + 0xd4);
    break;
  case 4:
    FUN_80148bc8(s_walk_patch_exit_8031d730);
    *(float *)(iVar16 + 0x14) = (float)dVar26;
    FUN_8013d5a4((double)FLOAT_803e2488,psVar3,iVar16,iVar16 + 0xec,1);
    cVar15 = FUN_80139a8c(psVar3,iVar16 + 0xec);
    break;
  case 5:
    FUN_80148bc8(s_curve_setup_8031d768);
    FUN_8013ab4c(psVar3,auStack156,(int)(short)uVar5,auStack124);
    iVar4 = FUN_8013a7f4(iVar16,auStack124,auStack156,*(undefined2 *)(iVar16 + 0x532));
    if (iVar4 == -1) {
      *(float *)(iVar16 + 0x14) = (float)dVar26;
      uVar7 = 2;
      goto LAB_8013d57c;
    }
    *(undefined *)(iVar16 + 0x41c) = auStack156[iVar4];
    *(undefined4 *)(iVar16 + 0x418) = auStack124[iVar4];
    *(float *)(iVar16 + 0x14) = (float)dVar26;
    FUN_8013d5a4((double)FLOAT_803e2488,psVar3,iVar16,*(int *)(iVar16 + 0x418) + 8,1);
    cVar15 = FUN_80139a8c(psVar3,*(int *)(iVar16 + 0x418) + 8);
    *(undefined *)(iVar16 + 9) = 6;
    break;
  case 6:
    dVar25 = (double)FUN_8002166c(*(int *)(iVar16 + 0x418) + 8,psVar3 + 0xc);
    local_58 = (longlong)(int)dVar25;
    FUN_80148bc8(s_walk_to_node__d__d_8031d754,10,(int)dVar25);
    dVar25 = (double)FUN_8002166c(*(int *)(iVar16 + 0x418) + 8,psVar3 + 0xc);
    if ((double)FLOAT_803e23e0 <= dVar25) {
      iVar4 = *(int *)(iVar16 + 0x418);
      if (iVar4 == 0) {
        iVar4 = 0;
      }
      else if (((*(short *)(iVar4 + 0x30) != -1) && (iVar19 = FUN_8001ffb4(), iVar19 == 0)) ||
              ((*(short *)(iVar4 + 0x32) != -1 && (iVar19 = FUN_8001ffb4(), iVar19 != 0)))) {
        iVar4 = 0;
      }
      if ((iVar4 == 0) && (uVar5 != 0)) {
        *(undefined *)(iVar16 + 9) = 0;
      }
      else {
        *(float *)(iVar16 + 0x14) = (float)dVar26;
        FUN_8013d5a4((double)FLOAT_803e246c,psVar3,iVar16,*(int *)(iVar16 + 0x418) + 8,1);
        cVar15 = FUN_80139a8c(psVar3,*(int *)(iVar16 + 0x418) + 8);
      }
    }
    else {
      *(uint *)(iVar16 + 0x4a0) = (uint)*(byte *)(iVar16 + 0x41c);
      iVar19 = *(int *)(iVar16 + 0x418);
      iVar4 = FUN_8013a9c8(iVar16,iVar19,*(undefined *)(iVar16 + 0x41c));
      if (iVar4 == 0) {
        *(undefined *)(iVar16 + 9) = 0;
      }
      else {
        iVar23 = FUN_8013a9c8(iVar16,iVar4,*(undefined *)(iVar16 + 0x41c));
        if (iVar23 == 0) {
          *(undefined *)(iVar16 + 9) = 0;
        }
        else {
          FUN_800da980(iVar16 + 0x420,iVar19,iVar4);
          FUN_800da928((double)FLOAT_803e2484,iVar16 + 0x420);
          sVar11 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(psVar3 + 6)),
                                (double)(*(float *)(iVar16 + 0x94) - *(float *)(psVar3 + 10)));
          sVar13 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(iVar16 + 0x488)),
                                (double)(*(float *)(iVar16 + 0x94) - *(float *)(iVar16 + 0x490)));
          sVar11 = sVar11 - sVar13;
          if (0x8000 < sVar11) {
            sVar11 = sVar11 + 1;
          }
          if (sVar11 < -0x8000) {
            sVar11 = sVar11 + -1;
          }
          if (sVar11 < 0x4001) {
            if (sVar11 < -0x4000) {
              sVar11 = sVar11 + -0x8000;
            }
          }
          else {
            sVar11 = sVar11 + -0x8000;
          }
          iVar4 = (int)sVar11;
          if (iVar4 < 0) {
            iVar4 = -iVar4;
          }
          if (0x1000 < iVar4) {
            *(float *)(iVar16 + 0x14) = (float)dVar26;
            FUN_8013d5a4((double)FLOAT_803e246c,psVar3,iVar16,iVar16 + 0x488,1);
          }
          FUN_80139834((double)*(float *)(iVar16 + 0x14),psVar3,iVar16 + 0x420);
          cVar15 = FUN_80139a8c(psVar3,iVar16 + 0x488);
          cVar14 = *(char *)(iVar19 + 0x1a);
          if (cVar14 == '\x05') {
            *(float *)(iVar16 + 0x2c) =
                 *(float *)(*(int *)(iVar16 + 0x4c0) + 8) - *(float *)(psVar3 + 0xc);
            *(float *)(iVar16 + 0x30) =
                 *(float *)(*(int *)(iVar16 + 0x4c0) + 0x10) - *(float *)(psVar3 + 0x10);
            dVar26 = (double)FUN_802931a0((double)(*(float *)(iVar16 + 0x2c) *
                                                   *(float *)(iVar16 + 0x2c) +
                                                  *(float *)(iVar16 + 0x30) *
                                                  *(float *)(iVar16 + 0x30)));
            if ((double)FLOAT_803e23dc != dVar26) {
              *(float *)(iVar16 + 0x2c) = (float)((double)*(float *)(iVar16 + 0x2c) / dVar26);
              *(float *)(iVar16 + 0x30) = (float)((double)*(float *)(iVar16 + 0x30) / dVar26);
            }
            iVar4 = FUN_800221a0(0,1);
            if (iVar4 == 0) {
              FUN_8013a3f0((double)FLOAT_803e2494,psVar3,0x18,0x40000c0);
            }
            else {
              FUN_8013a3f0((double)FLOAT_803e2490,psVar3,0x17,0x40000c0);
            }
            *(float *)(iVar16 + 0x48) =
                 (*(float *)(*(int *)(iVar16 + 0x4c0) + 0xc) - *(float *)(psVar3 + 0xe)) /
                 FLOAT_803e2498;
            *(undefined *)(iVar16 + 9) = 0xc;
            if (*(int *)(iVar16 + 0x4a0) == 0) {
              while (*(int *)(iVar16 + 0x430) == 0) {
                FUN_800da928((double)FLOAT_803e23f8,iVar16 + 0x420);
              }
            }
            else {
              while (*(int *)(iVar16 + 0x430) != 0) {
                FUN_800da928((double)FLOAT_803e2448,iVar16 + 0x420);
              }
            }
            *(float *)(iVar16 + 0x7a0) = FLOAT_803e2440;
          }
          else if (cVar14 < '\x05') {
            if (cVar14 == '\x02') {
LAB_8013c298:
              *(uint *)(iVar16 + 0x54) = *(uint *)(iVar16 + 0x54) | 0x2000;
            }
            else if ((cVar14 < '\x02') && ('\0' < cVar14)) {
              *(float *)(iVar16 + 0x2c) =
                   *(float *)(*(int *)(iVar16 + 0x4c0) + 8) - *(float *)(psVar3 + 0xc);
              *(float *)(iVar16 + 0x30) =
                   *(float *)(*(int *)(iVar16 + 0x4c0) + 0x10) - *(float *)(psVar3 + 0x10);
              dVar26 = (double)FUN_802931a0((double)(*(float *)(iVar16 + 0x2c) *
                                                     *(float *)(iVar16 + 0x2c) +
                                                    *(float *)(iVar16 + 0x30) *
                                                    *(float *)(iVar16 + 0x30)));
              if ((double)FLOAT_803e23dc != dVar26) {
                *(float *)(iVar16 + 0x2c) = (float)((double)*(float *)(iVar16 + 0x2c) / dVar26);
                *(float *)(iVar16 + 0x30) = (float)((double)*(float *)(iVar16 + 0x30) / dVar26);
              }
              *(float *)(iVar16 + 0x14) = FLOAT_803e248c;
              FUN_8013a3f0((double)FLOAT_803e2468,psVar3,0x15,0x4000000);
              *(undefined *)(iVar16 + 9) = 9;
              *(float *)(iVar16 + 0x7a0) = FLOAT_803e2440;
              break;
            }
LAB_8013c2a4:
            *(undefined *)(iVar16 + 9) = 7;
          }
          else {
            if (cVar14 == '\a') goto LAB_8013c298;
            if ('\x06' < cVar14) goto LAB_8013c2a4;
            *(float *)(iVar16 + 0x2c) =
                 *(float *)(*(int *)(iVar16 + 0x4c0) + 8) - *(float *)(psVar3 + 0xc);
            *(float *)(iVar16 + 0x30) =
                 *(float *)(*(int *)(iVar16 + 0x4c0) + 0x10) - *(float *)(psVar3 + 0x10);
            dVar26 = (double)FUN_802931a0((double)(*(float *)(iVar16 + 0x2c) *
                                                   *(float *)(iVar16 + 0x2c) +
                                                  *(float *)(iVar16 + 0x30) *
                                                  *(float *)(iVar16 + 0x30)));
            if ((double)FLOAT_803e23dc != dVar26) {
              *(float *)(iVar16 + 0x2c) = (float)((double)*(float *)(iVar16 + 0x2c) / dVar26);
              *(float *)(iVar16 + 0x30) = (float)((double)*(float *)(iVar16 + 0x30) / dVar26);
            }
            FUN_8013a3f0((double)FLOAT_803e249c,psVar3,0x19,0x40000c0);
            *(float *)(iVar16 + 0x48) =
                 (*(float *)(psVar3 + 0xe) - *(float *)(*(int *)(iVar16 + 0x4c0) + 0xc)) /
                 FLOAT_803e24a0;
            *(undefined *)(iVar16 + 9) = 0xe;
            if (*(int *)(iVar16 + 0x4a0) == 0) {
              while (*(int *)(iVar16 + 0x430) == 0) {
                FUN_800da928((double)FLOAT_803e23f8,iVar16 + 0x420);
              }
            }
            else {
              while (*(int *)(iVar16 + 0x430) != 0) {
                FUN_800da928((double)FLOAT_803e2448,iVar16 + 0x420);
              }
            }
            *(float *)(iVar16 + 0x7a0) = FLOAT_803e2440;
          }
        }
      }
    }
    break;
  case 7:
    FUN_80148bc8(s_walk_nodes_8031d778);
    if ((*(ushort *)(iVar16 + 0x534) != 0) && (uVar5 == *(ushort *)(iVar16 + 0x534))) {
      fVar1 = (float)((double)FLOAT_803e241c * (double)FLOAT_803db414 + dVar26);
      if (fVar1 < FLOAT_803e23dc) {
        fVar1 = FLOAT_803e23dc;
      }
      *(float *)(iVar16 + 0x14) = fVar1;
    }
    iVar4 = *(int *)(iVar16 + 0x4c0);
    if ((*(char *)(*(int *)(iVar16 + 0x4bc) + 0x1a) != '\t') && (*(char *)(iVar4 + 0x1a) != '\t')) {
      pfVar10 = *(float **)(iVar16 + 0x28);
      local_88 = *pfVar10 - *(float *)(psVar3 + 0xc);
      local_84 = pfVar10[1] - *(float *)(psVar3 + 0xe);
      local_80 = pfVar10[2] - *(float *)(psVar3 + 0x10);
      local_a4 = -*psVar3;
      local_a2 = 0;
      local_a0 = 0;
      FUN_80021ac8(&local_a4,&local_88);
      if ((FLOAT_803e23dc < local_80) && (FLOAT_803e23dc != *(float *)(iVar16 + 0x14))) {
        bVar18 = 0;
        while ((bVar18 < 4 && ((ushort)*(byte *)(iVar4 + bVar18 + 4) != *(ushort *)(iVar16 + 0x532))
               )) {
          bVar18 = bVar18 + 1;
        }
        if (bVar18 == 4) {
          FUN_8004b31c(iVar16 + 0x538,*(undefined4 *)(iVar16 + 0x4c4),*(undefined4 *)(iVar16 + 0x28)
                       ,*(undefined2 *)(iVar16 + 0x532),*(undefined4 *)(iVar16 + 0x4a0));
          FUN_8004b31c(iVar16 + 0x568,*(undefined4 *)(iVar16 + 0x4bc),*(undefined4 *)(iVar16 + 0x28)
                       ,*(undefined2 *)(iVar16 + 0x532),*(uint *)(iVar16 + 0x4a0) ^ 1);
          cVar14 = '\0';
          bVar18 = 0;
          while ((bVar18 = bVar18 + 1, bVar18 < 100 && (cVar14 != '\x01'))) {
            cVar14 = FUN_8004b218(iVar16 + 0x538,1);
            if (cVar14 != '\x01') {
              cVar14 = FUN_8004b218(iVar16 + 0x568,1);
              if (cVar14 != '\0') {
                if (cVar14 < '\0') {
                  if (-2 < cVar14) {
                    cVar14 = '\x01';
                  }
                }
                else if (cVar14 < '\x02') {
                  uVar6 = (*(uint *)(iVar16 + 0x4a0) ^ 1) & 0xff;
                  if (uVar6 == 0) {
                    FUN_800da928((double)FLOAT_803e23f8,iVar16 + 0x420);
                  }
                  else {
                    FUN_800da928((double)FLOAT_803e2448,iVar16 + 0x420);
                  }
                  *(uint *)(iVar16 + 0x4a0) = uVar6;
                  FUN_800d9ee8(iVar16 + 0x420);
                }
              }
            }
          }
        }
      }
    }
    uVar6 = *(uint *)(iVar16 + 0x4a0);
    if (((uVar6 == 0) && (*(int *)(iVar16 + 0x430) != 0)) ||
       ((uVar6 != 0 && (*(int *)(iVar16 + 0x430) == 0)))) {
      iVar4 = FUN_8013a9c8(iVar16,*(undefined4 *)(iVar16 + 0x4c4),uVar6 & 0xff);
      if (iVar4 != 0) {
        FUN_800da23c(iVar16 + 0x420);
        cVar15 = *(char *)(*(int *)(iVar16 + 0x4bc) + 0x1a);
        if ((cVar15 == '\a') || ((cVar15 < '\a' && (cVar15 == '\x02')))) {
          uVar6 = *(uint *)(iVar16 + 0x54);
          if ((uVar6 & 0x2000) == 0) {
            *(uint *)(iVar16 + 0x54) = uVar6 | 0x2000;
          }
          else {
            *(uint *)(iVar16 + 0x54) = uVar6 & 0xffffdfff;
          }
        }
        goto LAB_8013c6e4;
      }
      *(undefined *)(iVar16 + 9) = 0;
    }
    else {
      iVar4 = FUN_8013a9c8(iVar16,*(undefined4 *)(iVar16 + 0x4c0),uVar6 & 0xff);
      if (iVar4 == 0) {
        *(undefined *)(iVar16 + 9) = 0;
      }
      else {
        if (iVar4 != *(int *)(iVar16 + 0x4c4)) {
          FUN_800d9f38(iVar16 + 0x420);
        }
LAB_8013c6e4:
        if ((*(ushort *)(iVar16 + 0x534) == 0) || (uVar5 != *(ushort *)(iVar16 + 0x534))) {
          sVar11 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(psVar3 + 6)),
                                (double)(*(float *)(iVar16 + 0x94) - *(float *)(psVar3 + 10)));
          sVar13 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(iVar16 + 0x488)),
                                (double)(*(float *)(iVar16 + 0x94) - *(float *)(iVar16 + 0x490)));
          sVar11 = sVar11 - sVar13;
          if (0x8000 < sVar11) {
            sVar11 = sVar11 + 1;
          }
          if (sVar11 < -0x8000) {
            sVar11 = sVar11 + -1;
          }
          if (sVar11 < 0x4001) {
            if (sVar11 < -0x4000) {
              sVar11 = sVar11 + -0x8000;
            }
          }
          else {
            sVar11 = sVar11 + -0x8000;
          }
          iVar4 = (int)sVar11;
          if (iVar4 < 0) {
            iVar4 = -iVar4;
          }
          if (0x1000 < iVar4) {
            *(float *)(iVar16 + 0x14) = (float)dVar26;
            FUN_8013d5a4((double)FLOAT_803e246c,psVar3,iVar16,iVar16 + 0x488,1);
          }
        }
        FUN_80139834((double)*(float *)(iVar16 + 0x14),psVar3,iVar16 + 0x420);
        cVar15 = FUN_80139a8c(psVar3,iVar16 + 0x488);
        cVar14 = *(char *)(*(int *)(iVar16 + 0x4c0) + 0x1a);
        if (cVar14 == '\x05') {
          *(undefined *)(iVar16 + 9) = 0xb;
        }
        else if (cVar14 < '\x05') {
          if (cVar14 == '\x01') {
            *(undefined *)(iVar16 + 9) = 8;
          }
        }
        else if (cVar14 < '\a') {
          *(undefined *)(iVar16 + 9) = 0xd;
        }
      }
    }
    break;
  case 8:
    FUN_80148bc8(s_Jump_run_up_8031d784);
    fVar1 = (float)((double)FLOAT_803e2420 * (double)FLOAT_803db414 + dVar26);
    if (FLOAT_803e248c < fVar1) {
      fVar1 = FLOAT_803e248c;
    }
    *(float *)(iVar16 + 0x14) = fVar1;
    if ((*(ushort *)(iVar16 + 0x534) != 0) && (uVar5 == *(ushort *)(iVar16 + 0x534))) {
      fVar1 = (float)((double)FLOAT_803e241c * (double)FLOAT_803db414 + dVar26);
      if (fVar1 < FLOAT_803e23dc) {
        fVar1 = FLOAT_803e23dc;
      }
      *(float *)(iVar16 + 0x14) = fVar1;
    }
    sVar11 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(psVar3 + 6)),
                          (double)(*(float *)(iVar16 + 0x94) - *(float *)(psVar3 + 10)));
    sVar13 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(iVar16 + 0x488)),
                          (double)(*(float *)(iVar16 + 0x94) - *(float *)(iVar16 + 0x490)));
    sVar11 = sVar11 - sVar13;
    if (0x8000 < sVar11) {
      sVar11 = sVar11 + 1;
    }
    if (sVar11 < -0x8000) {
      sVar11 = sVar11 + -1;
    }
    if (sVar11 < 0x4001) {
      if (sVar11 < -0x4000) {
        sVar11 = sVar11 + -0x8000;
      }
    }
    else {
      sVar11 = sVar11 + -0x8000;
    }
    iVar4 = (int)sVar11;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
    }
    if (0x1000 < iVar4) {
      *(float *)(iVar16 + 0x14) = (float)dVar26;
      FUN_8013d5a4((double)FLOAT_803e246c,psVar3,iVar16,iVar16 + 0x488,1);
    }
    FUN_80139834((double)*(float *)(iVar16 + 0x14),psVar3,iVar16 + 0x420);
    FUN_80139a8c(psVar3,iVar16 + 0x488);
    uVar5 = *(uint *)(iVar16 + 0x4a0);
    if (((uVar5 == 0) && (*(int *)(iVar16 + 0x430) != 0)) ||
       ((uVar5 != 0 && (*(int *)(iVar16 + 0x430) == 0)))) {
      iVar4 = FUN_8013a9c8(iVar16,*(undefined4 *)(iVar16 + 0x4c4),uVar5 & 0xff);
      if (iVar4 == 0) {
        *(undefined *)(iVar16 + 9) = 0;
      }
      else {
        FUN_800da23c(iVar16 + 0x420);
        *(float *)(iVar16 + 0x2c) =
             *(float *)(*(int *)(iVar16 + 0x4c0) + 8) - *(float *)(psVar3 + 0xc);
        *(float *)(iVar16 + 0x30) =
             *(float *)(*(int *)(iVar16 + 0x4c0) + 0x10) - *(float *)(psVar3 + 0x10);
        dVar26 = (double)FUN_802931a0((double)(*(float *)(iVar16 + 0x2c) * *(float *)(iVar16 + 0x2c)
                                              + *(float *)(iVar16 + 0x30) *
                                                *(float *)(iVar16 + 0x30)));
        if ((double)FLOAT_803e23dc != dVar26) {
          *(float *)(iVar16 + 0x2c) = (float)((double)*(float *)(iVar16 + 0x2c) / dVar26);
          *(float *)(iVar16 + 0x30) = (float)((double)*(float *)(iVar16 + 0x30) / dVar26);
        }
        *(float *)(iVar16 + 0x14) = FLOAT_803e248c;
        FUN_8013a3f0((double)FLOAT_803e2468,psVar3,0x15,0x4000000);
        *(undefined *)(iVar16 + 9) = 9;
        *(float *)(iVar16 + 0x7a0) = FLOAT_803e2440;
      }
    }
    break;
  case 9:
    FUN_80148bc8(s_Jump_prep_8031d794);
    dVar25 = (double)FLOAT_803e24a4;
    if (dVar26 <= dVar25) {
      dVar26 = (double)(float)((double)FLOAT_803e2420 * (double)FLOAT_803db414 + dVar26);
      if (dVar25 < dVar26) {
        dVar26 = dVar25;
      }
    }
    else {
      dVar26 = (double)(float)((double)FLOAT_803e241c * (double)FLOAT_803db414 + dVar26);
      if (dVar26 < dVar25) {
        dVar26 = dVar25;
      }
    }
    *(float *)(iVar16 + 0x14) = (float)dVar26;
    dVar25 = (double)*(float *)(*(int *)(psVar3 + 0x5c) + 0x2c);
    dVar26 = (double)*(float *)(*(int *)(psVar3 + 0x5c) + 0x30);
    if (FLOAT_803e23ec < (float)(dVar25 * dVar25) + (float)(dVar26 * dVar26)) {
      sVar11 = FUN_800217c0(-dVar25,-dVar26);
      FUN_80139930(psVar3,(int)sVar11);
    }
    if (FLOAT_803e24a8 <= *(float *)(psVar3 + 0x4c)) {
      FUN_8002f5d4((double)(*(float *)(iVar16 + 0x14) * FLOAT_803e24ac),psVar3,iVar16 + 0x34);
      fVar1 = FLOAT_803e24ac;
      *(float *)(psVar3 + 6) =
           FLOAT_803db414 * *(float *)(iVar16 + 0x2c) * *(float *)(iVar16 + 0x14) * FLOAT_803e24ac +
           *(float *)(psVar3 + 6);
      *(float *)(psVar3 + 10) =
           FLOAT_803db414 * *(float *)(iVar16 + 0x30) * *(float *)(iVar16 + 0x14) * fVar1 +
           *(float *)(psVar3 + 10);
    }
    else {
      FUN_8002f5d4((double)*(float *)(iVar16 + 0x14),psVar3,iVar16 + 0x34);
      *(float *)(psVar3 + 6) =
           FLOAT_803db414 * *(float *)(iVar16 + 0x2c) * *(float *)(iVar16 + 0x14) +
           *(float *)(psVar3 + 6);
      *(float *)(psVar3 + 10) =
           FLOAT_803db414 * *(float *)(iVar16 + 0x30) * *(float *)(iVar16 + 0x14) +
           *(float *)(psVar3 + 10);
    }
    if ((*(uint *)(iVar16 + 0x54) & 0x8000000) != 0) {
      iVar4 = *(int *)(iVar16 + 0x4c0);
      fVar1 = *(float *)(iVar4 + 8) - *(float *)(psVar3 + 0xc);
      fVar2 = *(float *)(iVar4 + 0x10) - *(float *)(psVar3 + 0x10);
      dVar26 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
      *(float *)(iVar16 + 100) = (float)(dVar26 / (double)FLOAT_803e24a4);
      *(float *)(iVar16 + 0x68) = FLOAT_803e23dc;
      *(undefined4 *)(iVar16 + 0x74) = *(undefined4 *)(psVar3 + 0xc);
      *(undefined4 *)(iVar16 + 0x70) = *(undefined4 *)(psVar3 + 0xe);
      *(undefined4 *)(iVar16 + 0x78) = *(undefined4 *)(psVar3 + 0x10);
      *(undefined4 *)(iVar16 + 0x7c) = *(undefined4 *)(iVar4 + 8);
      *(undefined4 *)(iVar16 + 0x80) = *(undefined4 *)(iVar4 + 0x10);
      fVar1 = *(float *)(iVar16 + 100);
      *(float *)(iVar16 + 0x6c) =
           -(FLOAT_803e24b0 * fVar1 * fVar1 - (*(float *)(iVar4 + 0xc) - *(float *)(psVar3 + 0xe)))
           / fVar1;
      FUN_8013a3f0(psVar3,0x16,0x4000000);
      *(float *)(iVar16 + 0x3c) = *(float *)(iVar16 + 0x68) / *(float *)(iVar16 + 100);
      *(float *)(iVar16 + 0x14) = FLOAT_803e24a4;
      *(undefined *)(iVar16 + 9) = 10;
      if (*(int *)(iVar16 + 0x4a0) == 0) {
        while (*(int *)(iVar16 + 0x430) == 0) {
          FUN_800da928((double)FLOAT_803e23f8,iVar16 + 0x420);
        }
      }
      else {
        while (*(int *)(iVar16 + 0x430) != 0) {
          FUN_800da928((double)FLOAT_803e2448,iVar16 + 0x420);
        }
      }
    }
    break;
  case 10:
    FUN_80148bc8(s_Jumping_8031d7a0);
    *(float *)(iVar16 + 0x68) = *(float *)(iVar16 + 0x68) + FLOAT_803db414;
    if (*(float *)(iVar16 + 0x68) < *(float *)(iVar16 + 100)) {
      *(float *)(psVar3 + 6) =
           (*(float *)(iVar16 + 0x7c) - *(float *)(iVar16 + 0x74)) *
           (*(float *)(iVar16 + 0x68) / *(float *)(iVar16 + 100)) + *(float *)(iVar16 + 0x74);
      fVar1 = *(float *)(iVar16 + 0x68);
      *(float *)(psVar3 + 8) =
           FLOAT_803e24b0 * fVar1 * fVar1 +
           *(float *)(iVar16 + 0x6c) * fVar1 + *(float *)(iVar16 + 0x70);
      *(float *)(psVar3 + 10) =
           (*(float *)(iVar16 + 0x80) - *(float *)(iVar16 + 0x78)) *
           (*(float *)(iVar16 + 0x68) / *(float *)(iVar16 + 100)) + *(float *)(iVar16 + 0x78);
      fVar1 = *(float *)(iVar16 + 100);
      if (FLOAT_803e24b4 < fVar1) {
        fVar2 = *(float *)(iVar16 + 0x68);
        if (FLOAT_803e24b8 < fVar2) {
          if (fVar2 < fVar1 - FLOAT_803e24b8) {
            *(float *)(iVar16 + 0x3c) =
                 ((fVar2 - FLOAT_803e24b8) / (fVar1 - FLOAT_803e24bc)) * FLOAT_803e24a8 +
                 FLOAT_803e24ac;
          }
          else {
            *(float *)(iVar16 + 0x3c) = ((FLOAT_803e24b4 - fVar1) + fVar2) / FLOAT_803e24b4;
          }
        }
        else {
          *(float *)(iVar16 + 0x3c) = fVar2 / FLOAT_803e24b4;
        }
      }
      else {
        *(float *)(iVar16 + 0x3c) = *(float *)(iVar16 + 0x68) / fVar1;
      }
      FUN_80062e84(psVar3,0,0);
      *(undefined *)(iVar16 + 0x353) = 0;
    }
    else {
      *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(*(int *)(iVar16 + 0x4c0) + 0xc);
      *(float *)(iVar16 + 0x3c) = FLOAT_803e23e8;
      *(undefined *)(iVar16 + 9) = 7;
    }
    break;
  case 0xb:
    FUN_80148bc8(s_Jump_up_run_up_8031d7ac);
    fVar1 = (float)((double)FLOAT_803e2420 * (double)FLOAT_803db414 + dVar26);
    if (FLOAT_803e248c < fVar1) {
      fVar1 = FLOAT_803e248c;
    }
    *(float *)(iVar16 + 0x14) = fVar1;
    if ((*(ushort *)(iVar16 + 0x534) != 0) && (uVar5 == *(ushort *)(iVar16 + 0x534))) {
      fVar1 = (float)((double)FLOAT_803e241c * (double)FLOAT_803db414 + dVar26);
      if (fVar1 < FLOAT_803e23dc) {
        fVar1 = FLOAT_803e23dc;
      }
      *(float *)(iVar16 + 0x14) = fVar1;
    }
    sVar11 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(psVar3 + 6)),
                          (double)(*(float *)(iVar16 + 0x94) - *(float *)(psVar3 + 10)));
    sVar13 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(iVar16 + 0x488)),
                          (double)(*(float *)(iVar16 + 0x94) - *(float *)(iVar16 + 0x490)));
    sVar11 = sVar11 - sVar13;
    if (0x8000 < sVar11) {
      sVar11 = sVar11 + 1;
    }
    if (sVar11 < -0x8000) {
      sVar11 = sVar11 + -1;
    }
    if (sVar11 < 0x4001) {
      if (sVar11 < -0x4000) {
        sVar11 = sVar11 + -0x8000;
      }
    }
    else {
      sVar11 = sVar11 + -0x8000;
    }
    iVar4 = (int)sVar11;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
    }
    if (0x1000 < iVar4) {
      *(float *)(iVar16 + 0x14) = (float)dVar26;
      FUN_8013d5a4((double)FLOAT_803e246c,psVar3,iVar16,iVar16 + 0x488,1);
    }
    FUN_80139834((double)*(float *)(iVar16 + 0x14),psVar3,iVar16 + 0x420);
    FUN_80139a8c(psVar3,iVar16 + 0x488);
    uVar5 = *(uint *)(iVar16 + 0x4a0);
    if (((uVar5 == 0) && (*(int *)(iVar16 + 0x430) != 0)) ||
       ((uVar5 != 0 && (*(int *)(iVar16 + 0x430) == 0)))) {
      iVar4 = FUN_8013a9c8(iVar16,*(undefined4 *)(iVar16 + 0x4c4),uVar5 & 0xff);
      if (iVar4 == 0) {
        *(undefined *)(iVar16 + 9) = 0;
      }
      else {
        FUN_800da23c(iVar16 + 0x420);
        *(float *)(iVar16 + 0x2c) =
             *(float *)(*(int *)(iVar16 + 0x4c0) + 8) - *(float *)(psVar3 + 0xc);
        *(float *)(iVar16 + 0x30) =
             *(float *)(*(int *)(iVar16 + 0x4c0) + 0x10) - *(float *)(psVar3 + 0x10);
        dVar26 = (double)FUN_802931a0((double)(*(float *)(iVar16 + 0x2c) * *(float *)(iVar16 + 0x2c)
                                              + *(float *)(iVar16 + 0x30) *
                                                *(float *)(iVar16 + 0x30)));
        if ((double)FLOAT_803e23dc != dVar26) {
          *(float *)(iVar16 + 0x2c) = (float)((double)*(float *)(iVar16 + 0x2c) / dVar26);
          *(float *)(iVar16 + 0x30) = (float)((double)*(float *)(iVar16 + 0x30) / dVar26);
        }
        iVar4 = FUN_800221a0(0,1);
        if (iVar4 == 0) {
          FUN_8013a3f0((double)FLOAT_803e2494,psVar3,0x18,0x40000c0);
        }
        else {
          FUN_8013a3f0((double)FLOAT_803e2490,psVar3,0x17,0x40000c0);
        }
        *(float *)(iVar16 + 0x48) =
             (*(float *)(*(int *)(iVar16 + 0x4c0) + 0xc) - *(float *)(psVar3 + 0xe)) /
             FLOAT_803e2498;
        *(undefined *)(iVar16 + 9) = 0xc;
        if (*(int *)(iVar16 + 0x4a0) == 0) {
          while (*(int *)(iVar16 + 0x430) == 0) {
            FUN_800da928((double)FLOAT_803e23f8,iVar16 + 0x420);
          }
        }
        else {
          while (*(int *)(iVar16 + 0x430) != 0) {
            FUN_800da928((double)FLOAT_803e2448,iVar16 + 0x420);
          }
        }
        *(float *)(iVar16 + 0x7a0) = FLOAT_803e2440;
      }
    }
    break;
  case 0xc:
  case 0xe:
    FUN_80148bc8(s_JUMPDOWN_or_JUMPUP_8031d7bc);
    *(undefined *)(iVar16 + 0x353) = 0;
    FUN_80139834((double)*(float *)(iVar16 + 0x14),psVar3,iVar16 + 0x420);
    dVar25 = (double)*(float *)(*(int *)(psVar3 + 0x5c) + 0x2c);
    dVar26 = (double)*(float *)(*(int *)(psVar3 + 0x5c) + 0x30);
    if (FLOAT_803e23ec < (float)(dVar25 * dVar25) + (float)(dVar26 * dVar26)) {
      sVar11 = FUN_800217c0(-dVar25,-dVar26);
      FUN_80139930(psVar3,(int)sVar11);
    }
    if ((*(uint *)(iVar16 + 0x54) & 0x8000000) != 0) {
      *(float *)(iVar16 + 0x14) = FLOAT_803e24c0;
      FUN_80139a8c(psVar3,iVar16 + 0x488);
      *(undefined *)(iVar16 + 9) = 7;
    }
    break;
  case 0xd:
    FUN_80148bc8(s_JUMPDOWN_RUNUP_8031d7d0);
    fVar1 = (float)((double)FLOAT_803e2420 * (double)FLOAT_803db414 + dVar26);
    if (FLOAT_803e248c < fVar1) {
      fVar1 = FLOAT_803e248c;
    }
    *(float *)(iVar16 + 0x14) = fVar1;
    if ((*(ushort *)(iVar16 + 0x534) != 0) && (uVar5 == *(ushort *)(iVar16 + 0x534))) {
      fVar1 = (float)((double)FLOAT_803e241c * (double)FLOAT_803db414 + dVar26);
      if (fVar1 < FLOAT_803e23dc) {
        fVar1 = FLOAT_803e23dc;
      }
      *(float *)(iVar16 + 0x14) = fVar1;
    }
    sVar11 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(psVar3 + 6)),
                          (double)(*(float *)(iVar16 + 0x94) - *(float *)(psVar3 + 10)));
    sVar13 = FUN_800217c0((double)(*(float *)(iVar16 + 0x8c) - *(float *)(iVar16 + 0x488)),
                          (double)(*(float *)(iVar16 + 0x94) - *(float *)(iVar16 + 0x490)));
    sVar11 = sVar11 - sVar13;
    if (0x8000 < sVar11) {
      sVar11 = sVar11 + 1;
    }
    if (sVar11 < -0x8000) {
      sVar11 = sVar11 + -1;
    }
    if (sVar11 < 0x4001) {
      if (sVar11 < -0x4000) {
        sVar11 = sVar11 + -0x8000;
      }
    }
    else {
      sVar11 = sVar11 + -0x8000;
    }
    iVar4 = (int)sVar11;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
    }
    if (0x1000 < iVar4) {
      *(float *)(iVar16 + 0x14) = (float)dVar26;
      FUN_8013d5a4((double)FLOAT_803e246c,psVar3,iVar16,iVar16 + 0x488,1);
    }
    FUN_80139834((double)*(float *)(iVar16 + 0x14),psVar3,iVar16 + 0x420);
    FUN_80139a8c(psVar3,iVar16 + 0x488);
    uVar5 = *(uint *)(iVar16 + 0x4a0);
    if (((uVar5 == 0) && (*(int *)(iVar16 + 0x430) != 0)) ||
       ((uVar5 != 0 && (*(int *)(iVar16 + 0x430) == 0)))) {
      iVar4 = FUN_8013a9c8(iVar16,*(undefined4 *)(iVar16 + 0x4c4),uVar5 & 0xff);
      if (iVar4 == 0) {
        *(undefined *)(iVar16 + 9) = 0;
      }
      else {
        FUN_800da23c(iVar16 + 0x420);
        *(float *)(iVar16 + 0x2c) =
             *(float *)(*(int *)(iVar16 + 0x4c0) + 8) - *(float *)(psVar3 + 0xc);
        *(float *)(iVar16 + 0x30) =
             *(float *)(*(int *)(iVar16 + 0x4c0) + 0x10) - *(float *)(psVar3 + 0x10);
        dVar26 = (double)FUN_802931a0((double)(*(float *)(iVar16 + 0x2c) * *(float *)(iVar16 + 0x2c)
                                              + *(float *)(iVar16 + 0x30) *
                                                *(float *)(iVar16 + 0x30)));
        if ((double)FLOAT_803e23dc != dVar26) {
          *(float *)(iVar16 + 0x2c) = (float)((double)*(float *)(iVar16 + 0x2c) / dVar26);
          *(float *)(iVar16 + 0x30) = (float)((double)*(float *)(iVar16 + 0x30) / dVar26);
        }
        FUN_8013a3f0((double)FLOAT_803e249c,psVar3,0x19,0x40000c0);
        *(float *)(iVar16 + 0x48) =
             (*(float *)(psVar3 + 0xe) - *(float *)(*(int *)(iVar16 + 0x4c0) + 0xc)) /
             FLOAT_803e24a0;
        *(undefined *)(iVar16 + 9) = 0xe;
        if (*(int *)(iVar16 + 0x4a0) == 0) {
          while (*(int *)(iVar16 + 0x430) == 0) {
            FUN_800da928((double)FLOAT_803e23f8,iVar16 + 0x420);
          }
        }
        else {
          while (*(int *)(iVar16 + 0x430) != 0) {
            FUN_800da928((double)FLOAT_803e2448,iVar16 + 0x420);
          }
        }
        *(float *)(iVar16 + 0x7a0) = FLOAT_803e2440;
      }
    }
    break;
  default:
    FUN_80148bc8(s_entered_a_non_valid_movementstat_8031d7e0);
  }
  if (*(byte *)(iVar16 + 9) < 5) {
    iVar4 = FUN_800dbba4(psVar3 + 0xc);
    if (iVar4 == 0) {
      (**(code **)(*DAT_803dcaa8 + 0x20))(psVar3,iVar16 + 0xf8);
      *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(iVar16 + 0xe0);
      *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(iVar16 + 0xe4);
      *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(iVar16 + 0xe8);
      *(undefined4 *)(psVar3 + 0xc) = *(undefined4 *)(iVar16 + 0xe0);
      *(undefined4 *)(psVar3 + 0xe) = *(undefined4 *)(iVar16 + 0xe4);
      *(undefined4 *)(psVar3 + 0x10) = *(undefined4 *)(iVar16 + 0xe8);
      FUN_80035f8c(psVar3);
    }
    else {
      *(undefined4 *)(iVar16 + 0xe0) = *(undefined4 *)(psVar3 + 0xc);
      *(undefined4 *)(iVar16 + 0xe4) = *(undefined4 *)(psVar3 + 0xe);
      *(undefined4 *)(iVar16 + 0xe8) = *(undefined4 *)(psVar3 + 0x10);
    }
  }
  cVar14 = *(char *)(iVar16 + 9);
  if (((((cVar14 == '\0') || (cVar14 == '\x02')) || (cVar14 == '\x04')) || (cVar14 == '\x03')) &&
     (FLOAT_803e23dc == *(float *)(iVar16 + 0x14))) {
    uVar7 = 2;
  }
  else if (cVar15 == '\0') {
    uVar7 = 0;
  }
  else {
    uVar7 = 1;
  }
LAB_8013d57c:
  __psq_l0(auStack8,uVar24);
  __psq_l1(auStack8,uVar24);
  __psq_l0(auStack24,uVar24);
  __psq_l1(auStack24,uVar24);
  FUN_80286110(uVar7);
  return;
}

