// Function: FUN_80086178
// Entry: 80086178
// Size: 1728 bytes

/* WARNING: Removing unreachable block (ram,0x80086810) */
/* WARNING: Removing unreachable block (ram,0x80086818) */

void FUN_80086178(undefined4 param_1,undefined4 param_2,undefined4 *param_3,int param_4)

{
  short sVar1;
  ushort uVar2;
  bool bVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  byte bVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined2 uVar11;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  double dVar15;
  double in_f30;
  double in_f31;
  float local_68;
  char *local_64;
  undefined auStack96 [12];
  float local_54;
  float local_50;
  float local_4c;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  iVar8 = FUN_802860c8();
  if (param_3[0x25] != 0) {
    bVar7 = 1;
    if (param_4 != 0) {
      bVar7 = 3;
    }
    iVar12 = *(int *)(iVar8 + 0x4c);
    sVar1 = *(short *)(param_3 + 0x16);
    DAT_803dd08a = sVar1;
    *(undefined2 *)((int)param_3 + 0x66) = 0;
    *(undefined2 *)(param_3 + 0x1a) = 0xffce;
    *(undefined *)(param_3 + 0x1e) = 0;
    *(undefined *)((int)param_3 + 0x7a) = 0;
    *(undefined *)((int)param_3 + 0x79) = 0;
    *param_3 = 0;
    *(undefined *)((int)param_3 + 0x7b) = 0;
    param_3[8] = FLOAT_803defb0;
    *(undefined2 *)(param_3 + 0x16) = 0xffff;
    uVar11 = 0xffff;
    iVar13 = 0;
    iVar10 = iVar8;
    while ((iVar13 < *(short *)((int)param_3 + 0x62) && (*(short *)(param_3 + 0x16) <= sVar1))) {
      local_64 = (char *)(param_3[0x25] + iVar13 * 4);
      switch(*local_64) {
      case '\0':
        *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(local_64 + 2);
        break;
      default:
        if (*local_64 != '\x0f') {
          *(ushort *)(param_3 + 0x16) = *(short *)(param_3 + 0x16) + (ushort)(byte)local_64[1];
        }
        break;
      case '\x03':
        bVar7 = bVar7 | 4;
        iVar10 = FUN_80085dc4(iVar8,param_3,iVar12);
        *(undefined2 *)(iVar10 + 0xa2) = 0xffff;
        break;
      case '\t':
        uVar11 = *(undefined2 *)(param_3 + 0x16);
        break;
      case '\v':
        if (0 < *(short *)(local_64 + 2)) {
          iVar13 = iVar13 + *(short *)(local_64 + 2);
        }
      }
      iVar13 = iVar13 + 1;
    }
    *(undefined2 *)(param_3 + 0x16) = uVar11;
    iVar13 = *(int *)(*(int *)(iVar10 + 0x7c) + *(char *)(iVar10 + 0xad) * 4);
    if (iVar13 != 0) {
      if (param_3[0x26] == 0) {
        dVar15 = (double)FLOAT_803defb0;
      }
      else {
        dVar15 = (double)FLOAT_803defb0;
        if (*(ushort *)(param_3 + 0x37) != 0) {
          dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)((int)param_3 + 0xb6) * 8,
                                        *(ushort *)(param_3 + 0x37) & 0xfff,0xffffffff);
        }
      }
      in_f31 = (double)(float)((double)*(float *)(iVar12 + 8) + dVar15);
      if (param_3[0x26] == 0) {
        dVar15 = (double)FLOAT_803defb0;
      }
      else {
        dVar15 = (double)FLOAT_803defb0;
        if (*(ushort *)(param_3 + 0x36) != 0) {
          dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)((int)param_3 + 0xb2) * 8,
                                        *(ushort *)(param_3 + 0x36) & 0xfff,0xffffffff);
        }
      }
      in_f30 = (double)(float)((double)*(float *)(iVar12 + 0x10) + dVar15);
    }
    while (*(short *)(param_3 + 0x16) < sVar1) {
      *(short *)(param_3 + 0x16) = *(short *)(param_3 + 0x16) + 1;
      if (param_3[0x26] == 0) {
        dVar15 = (double)FLOAT_803defb0;
      }
      else {
        dVar15 = (double)FLOAT_803defb0;
        if (*(ushort *)(param_3 + 0x37) != 0) {
          dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)((int)param_3 + 0xb6) * 8,
                                        *(ushort *)(param_3 + 0x37) & 0xfff,
                                        (int)*(short *)(param_3 + 0x16));
        }
      }
      local_54 = (float)((double)*(float *)(iVar12 + 8) + dVar15);
      if (param_3[0x26] == 0) {
        dVar15 = (double)FLOAT_803defb0;
      }
      else {
        dVar15 = (double)FLOAT_803defb0;
        if (*(ushort *)((int)param_3 + 0xda) != 0) {
          dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)(param_3 + 0x2d) * 8,
                                        *(ushort *)((int)param_3 + 0xda) & 0xfff,
                                        (int)*(short *)(param_3 + 0x16));
        }
      }
      local_50 = (float)((double)*(float *)(iVar12 + 0xc) + dVar15);
      if (param_3[0x26] == 0) {
        dVar15 = (double)FLOAT_803defb0;
      }
      else {
        dVar15 = (double)FLOAT_803defb0;
        if (*(ushort *)(param_3 + 0x36) != 0) {
          dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)((int)param_3 + 0xb2) * 8,
                                        *(ushort *)(param_3 + 0x36) & 0xfff,
                                        (int)*(short *)(param_3 + 0x16));
        }
      }
      local_4c = (float)((double)*(float *)(iVar12 + 0x10) + dVar15);
      if ((0 < *(short *)(param_3 + 0x16)) && (param_4 != 0)) {
        if ((*(char *)(param_3 + 0x1e) == '\x01') &&
           ((*(char *)((int)param_3 + 0x7b) == '\0' && (iVar13 != 0)))) {
          FUN_802931a0((double)((float)((double)local_54 - in_f31) *
                                (float)((double)local_54 - in_f31) +
                               (float)((double)local_4c - in_f30) *
                               (float)((double)local_4c - in_f30)));
          iVar9 = FUN_8002f5d4(iVar10,&local_68);
          if (iVar9 == 0) {
            if (param_3[0x26] == 0) {
              dVar15 = (double)FLOAT_803defb0;
            }
            else {
              dVar15 = (double)FLOAT_803defb0;
              if (*(ushort *)(param_3 + 0x35) != 0) {
                dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)((int)param_3 + 0xae) * 8,
                                              *(ushort *)(param_3 + 0x35) & 0xfff,
                                              *(short *)(param_3 + 0x16) + -1);
              }
            }
            local_68 = (float)((double)FLOAT_803df030 * dVar15);
          }
        }
        else {
          if (param_3[0x26] == 0) {
            dVar15 = (double)FLOAT_803defb0;
          }
          else {
            dVar15 = (double)FLOAT_803defb0;
            if (*(ushort *)(param_3 + 0x35) != 0) {
              dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)((int)param_3 + 0xae) * 8,
                                            *(ushort *)(param_3 + 0x35) & 0xfff,
                                            *(short *)(param_3 + 0x16) + -1);
            }
          }
          local_68 = (float)((double)FLOAT_803df030 * dVar15);
        }
        if (iVar13 == 0) {
          *(float *)(iVar10 + 0x98) = *(float *)(iVar10 + 0x98) + local_68;
          fVar5 = FLOAT_803defc8;
          while (fVar6 = FLOAT_803defc8, fVar4 = FLOAT_803defb0, fVar5 < *(float *)(iVar10 + 0x98))
          {
            *(float *)(iVar10 + 0x98) = *(float *)(iVar10 + 0x98) - fVar5;
          }
          while (*(float *)(iVar10 + 0x98) < fVar4) {
            *(float *)(iVar10 + 0x98) = *(float *)(iVar10 + 0x98) + fVar6;
          }
        }
        else {
          FUN_8002fa48((double)local_68,(double)FLOAT_803defc8,iVar10,param_3 + 0x3c);
          if ((param_4 != 0) &&
             (dVar15 = (double)FLOAT_803defb0, dVar15 < (double)(float)param_3[8])) {
            uVar2 = *(ushort *)((int)param_3 + 0xd6);
            if (uVar2 == 0) {
              dVar15 = (double)FLOAT_803df034;
            }
            else if ((param_3[0x26] != 0) && (uVar2 != 0)) {
              dVar15 = (double)FUN_80082bf0(param_3[0x26] + *(short *)(param_3 + 0x2c) * 8,
                                            uVar2 & 0xfff,*(short *)(param_3 + 0x16) + -1);
            }
            if (dVar15 < (double)FLOAT_803defc8) {
              dVar15 = (double)FLOAT_803defc8;
            }
            param_3[8] = (float)param_3[8] - (float)((double)FLOAT_803defc8 / dVar15);
            if ((float)param_3[8] < FLOAT_803defb0) {
              param_3[8] = FLOAT_803defb0;
            }
          }
        }
      }
      in_f31 = (double)local_54;
      in_f30 = (double)local_4c;
      bVar3 = false;
      DAT_803dd0c0 = 0;
      while ((!bVar3 &&
             ((int)*(short *)((int)param_3 + 0x66) < (int)*(short *)((int)param_3 + 0x62)))) {
        local_64 = (char *)(param_3[0x25] + *(short *)((int)param_3 + 0x66) * 4);
        if (*local_64 == '\0') {
          if (*(short *)(param_3 + 0x16) < *(short *)(local_64 + 2)) {
            bVar3 = true;
          }
          else {
            *(short *)(param_3 + 0x1a) = *(short *)(local_64 + 2);
            *(short *)((int)param_3 + 0x66) = *(short *)((int)param_3 + 0x66) + 1;
          }
        }
        else if (*(short *)(param_3 + 0x16) < *(short *)(param_3 + 0x1a)) {
          bVar3 = true;
        }
        else {
          if (*local_64 != '\x0f') {
            *(ushort *)(param_3 + 0x1a) = *(short *)(param_3 + 0x1a) + (ushort)(byte)local_64[1];
          }
          *(short *)((int)param_3 + 0x66) = *(short *)((int)param_3 + 0x66) + 1;
          iVar10 = FUN_80085358(iVar8,iVar13,&local_64,bVar7,auStack96);
          if (iVar10 != 0) goto LAB_80086810;
          iVar10 = **(int **)(iVar8 + 0xb8);
          if (**(int **)(iVar8 + 0xb8) == 0) {
            iVar10 = iVar8;
          }
          iVar13 = *(int *)(*(int *)(iVar10 + 0x7c) + *(char *)(iVar10 + 0xad) * 4);
        }
      }
      for (iVar9 = 0; iVar9 < DAT_803dd0c0; iVar9 = iVar9 + 1) {
        iVar10 = FUN_80083710(iVar8,iVar10,param_3,(&DAT_8039944c)[iVar9 * 2],
                              (int)(short)(&DAT_80399452)[iVar9 * 4],
                              (int)(short)(&DAT_80399450)[iVar9 * 4],1,0);
        if (iVar10 != 0) {
          iVar9 = DAT_803dd0c0;
        }
        iVar10 = **(int **)(iVar8 + 0xb8);
        if (**(int **)(iVar8 + 0xb8) == 0) {
          iVar10 = iVar8;
        }
        iVar13 = *(int *)(*(int *)(iVar10 + 0x7c) + *(char *)(iVar10 + 0xad) * 4);
      }
      DAT_803dd0c0 = 0;
    }
  }
LAB_80086810:
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  FUN_80286114();
  return;
}

