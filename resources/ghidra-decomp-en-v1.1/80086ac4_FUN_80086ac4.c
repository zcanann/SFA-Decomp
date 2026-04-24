// Function: FUN_80086ac4
// Entry: 80086ac4
// Size: 2388 bytes

void FUN_80086ac4(undefined8 param_1,undefined8 param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7)

{
  short sVar1;
  int iVar2;
  bool bVar9;
  short *psVar3;
  uint *puVar4;
  short *psVar5;
  undefined2 *puVar6;
  int *piVar7;
  int *piVar8;
  int iVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  undefined8 uVar16;
  
  uVar16 = FUN_80286834();
  puVar6 = (undefined2 *)((ulonglong)uVar16 >> 0x20);
  iVar10 = (int)uVar16;
  iVar13 = *(int *)(puVar6 + 0x26);
  *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(iVar13 + 8);
  *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(iVar13 + 0xc);
  *(undefined4 *)(puVar6 + 10) = *(undefined4 *)(iVar13 + 0x10);
  puVar6[1] = 0;
  *puVar6 = 0;
  puVar6[2] = 0;
  if ((*(ushort *)(param_6 + 0x6e) & 0x20) != 0) {
    *(undefined *)(iVar10 + 0x36) = 0xff;
  }
  dVar14 = (double)FLOAT_803dfc30;
  FLOAT_803ddd4c = FLOAT_803dfc30;
  FLOAT_803ddd48 = FLOAT_803dfc30;
  FLOAT_803ddd44 = FLOAT_803dfc30;
  iVar2 = *(int *)(param_6 + 0x98);
  if (iVar2 == 0) {
    FLOAT_803ddda0 = FLOAT_803dfc30;
    FLOAT_803ddd9c = FLOAT_803dfc30;
    FLOAT_803ddd98 = FLOAT_803dfc30;
    DAT_803ddd96 = 0;
    DAT_803ddd94 = 1;
  }
  else {
    if ((iVar2 != 0) && ((int)*(short *)(param_6 + 0xe6) != 0)) {
      dVar14 = FUN_80082e7c(dVar14,param_2,param_3,(float *)(iVar2 + *(short *)(param_6 + 0xc0) * 8)
                            ,(int)*(short *)(param_6 + 0xe6) & 0xfff,param_7);
    }
    iVar12 = 0;
    iVar2 = param_6;
    do {
      if (*(short *)(iVar2 + 0x30) != 0) {
        FUN_8000b5f0(iVar10,*(short *)(iVar2 + 0x38));
      }
      iVar2 = iVar2 + 2;
      iVar12 = iVar12 + 1;
    } while (iVar12 < 3);
    if (((0 < (int)dVar14) && (*(short *)(param_6 + 0x36) != 0)) &&
       (bVar9 = FUN_8000b5f0(iVar10,*(short *)(param_6 + 0x3e)), bVar9)) {
      FUN_8000b9bc((double)FLOAT_803dfcb8,iVar10,*(short *)(param_6 + 0x3e),(byte)(int)dVar14);
    }
    if (*(int *)(param_6 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803dfc30;
    }
    else {
      dVar14 = (double)FLOAT_803dfc30;
      if ((int)*(short *)(param_6 + 0xd0) != 0) {
        dVar14 = FUN_80082e7c(dVar14,param_2,param_3,
                              (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xaa) * 8),
                              (int)*(short *)(param_6 + 0xd0) & 0xfff,param_7);
      }
    }
    *puVar6 = (short)(int)((double)FLOAT_803dfcbc * dVar14);
    if (*(int *)(param_6 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803dfc30;
    }
    else {
      dVar14 = (double)FLOAT_803dfc30;
      if ((int)*(short *)(param_6 + 0xd2) != 0) {
        dVar14 = FUN_80082e7c(dVar14,param_2,param_3,
                              (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xac) * 8),
                              (int)*(short *)(param_6 + 0xd2) & 0xfff,param_7);
      }
    }
    puVar6[1] = (short)(int)((double)FLOAT_803dfcbc * dVar14);
    if (*(int *)(param_6 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803dfc30;
    }
    else {
      dVar14 = (double)FLOAT_803dfc30;
      if ((int)*(short *)(param_6 + 0xce) != 0) {
        dVar14 = FUN_80082e7c(dVar14,param_2,param_3,
                              (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xa8) * 8),
                              (int)*(short *)(param_6 + 0xce) & 0xfff,param_7);
      }
    }
    puVar6[2] = (short)(int)((double)FLOAT_803dfcbc * dVar14);
    if (*(int *)(param_6 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803dfc30;
    }
    else {
      dVar14 = (double)FLOAT_803dfc30;
      if ((int)*(short *)(param_6 + 0xdc) != 0) {
        dVar14 = FUN_80082e7c(dVar14,param_2,param_3,
                              (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xb6) * 8),
                              (int)*(short *)(param_6 + 0xdc) & 0xfff,param_7);
      }
    }
    FLOAT_803ddd4c = (float)dVar14;
    if (*(int *)(param_6 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803dfc30;
    }
    else {
      dVar14 = (double)FLOAT_803dfc30;
      if ((int)*(short *)(param_6 + 0xda) != 0) {
        dVar14 = FUN_80082e7c(dVar14,param_2,param_3,
                              (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xb4) * 8),
                              (int)*(short *)(param_6 + 0xda) & 0xfff,param_7);
      }
    }
    FLOAT_803ddd48 = (float)dVar14;
    if (*(int *)(param_6 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803dfc30;
    }
    else {
      dVar14 = (double)FLOAT_803dfc30;
      if ((int)*(short *)(param_6 + 0xd8) != 0) {
        dVar14 = FUN_80082e7c(dVar14,param_2,param_3,
                              (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xb2) * 8),
                              (int)*(short *)(param_6 + 0xd8) & 0xfff,param_7);
      }
    }
    FLOAT_803ddd44 = (float)dVar14;
    dVar15 = (double)FLOAT_803ddd4c;
    FLOAT_803ddda0 = FLOAT_803ddd4c;
    FLOAT_803ddd9c = FLOAT_803ddd48;
    FLOAT_803ddd98 = (float)dVar14;
    DAT_803ddd96 = *puVar6;
    DAT_803ddd94 = 1;
    *(float *)(puVar6 + 6) = (float)((double)*(float *)(iVar13 + 8) + dVar15);
    *(float *)(puVar6 + 8) = *(float *)(iVar13 + 0xc) + FLOAT_803ddd48;
    *(float *)(puVar6 + 10) = *(float *)(iVar13 + 0x10) + FLOAT_803ddd44;
    uVar11 = (uint)*(short *)(param_6 + 0xde);
    if (uVar11 != 0) {
      if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xb8) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      if (*(char *)(param_6 + 0x7b) == '\0') {
        *(float *)(param_6 + 0x10) = (float)dVar14;
      }
      else {
        if (dVar14 < (double)FLOAT_803dfcc0) {
          dVar14 = (double)FLOAT_803dfcc0;
        }
        if ((double)FLOAT_803dfcc8 < dVar14) {
          dVar14 = (double)FLOAT_803dfcc4;
        }
        DAT_803ddd08 = 1;
        FLOAT_803ddd50 = (float)dVar14;
      }
    }
    if (((*(ushort *)(param_6 + 0x6e) & 0x20) != 0) &&
       (uVar11 = (uint)*(short *)(param_6 + 200), uVar11 != 0)) {
      if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xa2) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      if (dVar14 < (double)FLOAT_803dfc30) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      if ((double)FLOAT_803dfccc < dVar14) {
        dVar14 = (double)FLOAT_803dfccc;
      }
      *(char *)(iVar10 + 0x36) = (char)(int)dVar14;
    }
    uVar11 = (uint)*(short *)(param_6 + 0xca);
    if (uVar11 != 0) {
      if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xa4) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      (**(code **)(*DAT_803dd6d8 + 0x28))((double)(float)((double)FLOAT_803dfc7c * dVar14));
    }
    if (((*(ushort *)(param_6 + 0x6e) & 0x10) != 0) &&
       (uVar11 = (uint)*(short *)(param_6 + 0xcc), uVar11 != 0)) {
      if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xa6) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      *(float *)(iVar10 + 8) = (float)(dVar14 * (double)*(float *)(*(int *)(iVar10 + 0x50) + 4));
    }
    if (((*(ushort *)(param_6 + 0x6e) & 8) != 0) &&
       (psVar3 = (short *)FUN_800396d0(iVar10,0), psVar3 != (short *)0x0)) {
      uVar11 = (uint)*(short *)(param_6 + 0xc4);
      if (uVar11 == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0x9e) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      *psVar3 = *(short *)(param_6 + 0x116) + (short)(int)((double)FLOAT_803dfcbc * dVar14);
      uVar11 = (uint)*(short *)(param_6 + 0xc6);
      if (uVar11 == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xa0) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      psVar3[1] = *(short *)(param_6 + 0x114) + (short)(int)((double)FLOAT_803dfcbc * dVar14);
      uVar11 = (uint)*(short *)(param_6 + 0xc2);
      if (uVar11 == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0x9c) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      psVar3[2] = (short)(int)((double)FLOAT_803dfcbc * dVar14);
      if ((*(ushort *)(param_6 + 0x6e) & 0x400) != 0) {
        uVar11 = (uint)(*(byte *)(param_6 + 0x136) >> 4);
        puVar4 = FUN_80039598();
        if (uVar11 == 0) {
          uVar11 = 9;
        }
        if (psVar3 != (short *)0x0) {
          for (iVar13 = 1; puVar4 = puVar4 + 1, iVar13 < (int)uVar11; iVar13 = iVar13 + 1) {
            psVar5 = (short *)FUN_800396d0(iVar10,*puVar4);
            if (psVar5 != (short *)0x0) {
              psVar5[1] = psVar3[1];
              *psVar5 = *psVar3;
              psVar5[2] = psVar3[2];
            }
          }
        }
      }
    }
    if (((*(ushort *)(param_6 + 0x6e) & 0x200) != 0) &&
       (puVar6 = (undefined2 *)FUN_800396d0(iVar10,1), puVar6 != (undefined2 *)0x0)) {
      uVar11 = (uint)*(short *)(param_6 + 0xe4);
      if (uVar11 == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else if (*(int *)(param_6 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803dfc30;
      }
      else {
        dVar14 = (double)FLOAT_803dfc30;
        if (uVar11 != 0) {
          dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                (float *)(*(int *)(param_6 + 0x98) + *(short *)(param_6 + 0xbe) * 8)
                                ,uVar11 & 0xfff,param_7);
        }
      }
      *puVar6 = (short)(int)((double)FLOAT_803dfcbc * dVar14);
    }
    if ((*(ushort *)(param_6 + 0x6e) & 0x40) != 0) {
      iVar13 = FUN_800395a4(iVar10,1);
      iVar2 = FUN_800395a4(iVar10,0);
      if ((iVar13 != 0) || (iVar2 != 0)) {
        uVar11 = (uint)*(short *)(param_6 + 0xe0);
        if (uVar11 == 0) {
          dVar14 = (double)FLOAT_803dfc30;
        }
        else if (*(int *)(param_6 + 0x98) == 0) {
          dVar14 = (double)FLOAT_803dfc30;
        }
        else {
          dVar14 = (double)FLOAT_803dfc30;
          if (uVar11 != 0) {
            dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                  (float *)(*(int *)(param_6 + 0x98) +
                                           *(short *)(param_6 + 0xba) * 8),uVar11 & 0xfff,param_7);
          }
        }
        sVar1 = (short)(int)((double)FLOAT_803dfc84 * dVar14);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 8) = sVar1;
        }
        if (iVar2 != 0) {
          *(short *)(iVar2 + 8) = -sVar1;
        }
        uVar11 = (uint)*(short *)(param_6 + 0xe2);
        if (uVar11 == 0) {
          dVar14 = (double)FLOAT_803dfc30;
        }
        else if (*(int *)(param_6 + 0x98) == 0) {
          dVar14 = (double)FLOAT_803dfc30;
        }
        else {
          dVar14 = (double)FLOAT_803dfc30;
          if (uVar11 != 0) {
            dVar14 = FUN_80082e7c(dVar14,dVar15,param_3,
                                  (float *)(*(int *)(param_6 + 0x98) +
                                           *(short *)(param_6 + 0xbc) * 8),uVar11 & 0xfff,param_7);
          }
        }
        sVar1 = -(short)(int)((double)FLOAT_803dfc84 * dVar14);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 10) = sVar1;
        }
        if (iVar2 != 0) {
          *(short *)(iVar2 + 10) = sVar1;
        }
      }
      piVar7 = (int *)FUN_800395a4(iVar10,5);
      piVar8 = (int *)FUN_800395a4(iVar10,4);
      if (piVar7 != (int *)0x0) {
        *piVar7 = (int)(short)(ushort)*(byte *)(param_6 + 0x8d) << 8;
      }
      if (piVar8 != (int *)0x0) {
        *piVar8 = (int)(short)(ushort)*(byte *)(param_6 + 0x8e) << 8;
      }
    }
  }
  FUN_80286880();
  return;
}

