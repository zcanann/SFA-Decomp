// Function: FUN_80086838
// Entry: 80086838
// Size: 2388 bytes

void FUN_80086838(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  ushort uVar1;
  short sVar2;
  int iVar3;
  short *psVar4;
  undefined4 *puVar5;
  short *psVar6;
  undefined2 *puVar7;
  int *piVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  double dVar14;
  undefined8 uVar15;
  
  uVar15 = FUN_802860d0();
  puVar7 = (undefined2 *)((ulonglong)uVar15 >> 0x20);
  iVar10 = (int)uVar15;
  iVar13 = *(int *)(puVar7 + 0x26);
  *(undefined4 *)(puVar7 + 6) = *(undefined4 *)(iVar13 + 8);
  *(undefined4 *)(puVar7 + 8) = *(undefined4 *)(iVar13 + 0xc);
  *(undefined4 *)(puVar7 + 10) = *(undefined4 *)(iVar13 + 0x10);
  puVar7[1] = 0;
  *puVar7 = 0;
  puVar7[2] = 0;
  if ((*(ushort *)(param_3 + 0x6e) & 0x20) != 0) {
    *(undefined *)(iVar10 + 0x36) = 0xff;
  }
  dVar14 = (double)FLOAT_803defb0;
  FLOAT_803dd0cc = FLOAT_803defb0;
  FLOAT_803dd0c8 = FLOAT_803defb0;
  FLOAT_803dd0c4 = FLOAT_803defb0;
  iVar3 = *(int *)(param_3 + 0x98);
  if (iVar3 == 0) {
    FLOAT_803dd120 = FLOAT_803defb0;
    FLOAT_803dd11c = FLOAT_803defb0;
    FLOAT_803dd118 = FLOAT_803defb0;
    DAT_803dd116 = 0;
    DAT_803dd114 = 1;
  }
  else {
    if ((iVar3 != 0) && (*(ushort *)(param_3 + 0xe6) != 0)) {
      dVar14 = (double)FUN_80082bf0(iVar3 + *(short *)(param_3 + 0xc0) * 8,
                                    *(ushort *)(param_3 + 0xe6) & 0xfff,param_4);
    }
    iVar11 = 0;
    iVar3 = param_3;
    do {
      if (*(short *)(iVar3 + 0x30) != 0) {
        FUN_8000b5d0(iVar10,*(undefined2 *)(iVar3 + 0x38));
      }
      iVar3 = iVar3 + 2;
      iVar11 = iVar11 + 1;
    } while (iVar11 < 3);
    if (((0 < (int)dVar14) && (*(short *)(param_3 + 0x36) != 0)) &&
       (iVar3 = FUN_8000b5d0(iVar10,*(undefined2 *)(param_3 + 0x3e)), iVar3 != 0)) {
      FUN_8000b99c((double)FLOAT_803df038,iVar10,*(undefined2 *)(param_3 + 0x3e),(int)dVar14 & 0xff)
      ;
    }
    if (*(int *)(param_3 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803defb0;
    }
    else {
      dVar14 = (double)FLOAT_803defb0;
      if (*(ushort *)(param_3 + 0xd0) != 0) {
        dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xaa) * 8,
                                      *(ushort *)(param_3 + 0xd0) & 0xfff,param_4);
      }
    }
    *puVar7 = (short)(int)((double)FLOAT_803df03c * dVar14);
    if (*(int *)(param_3 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803defb0;
    }
    else {
      dVar14 = (double)FLOAT_803defb0;
      if (*(ushort *)(param_3 + 0xd2) != 0) {
        dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xac) * 8,
                                      *(ushort *)(param_3 + 0xd2) & 0xfff,param_4);
      }
    }
    puVar7[1] = (short)(int)((double)FLOAT_803df03c * dVar14);
    if (*(int *)(param_3 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803defb0;
    }
    else {
      dVar14 = (double)FLOAT_803defb0;
      if (*(ushort *)(param_3 + 0xce) != 0) {
        dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xa8) * 8,
                                      *(ushort *)(param_3 + 0xce) & 0xfff,param_4);
      }
    }
    puVar7[2] = (short)(int)((double)FLOAT_803df03c * dVar14);
    if (*(int *)(param_3 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803defb0;
    }
    else {
      dVar14 = (double)FLOAT_803defb0;
      if (*(ushort *)(param_3 + 0xdc) != 0) {
        dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xb6) * 8,
                                      *(ushort *)(param_3 + 0xdc) & 0xfff,param_4);
      }
    }
    FLOAT_803dd0cc = (float)dVar14;
    if (*(int *)(param_3 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803defb0;
    }
    else {
      dVar14 = (double)FLOAT_803defb0;
      if (*(ushort *)(param_3 + 0xda) != 0) {
        dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xb4) * 8,
                                      *(ushort *)(param_3 + 0xda) & 0xfff,param_4);
      }
    }
    FLOAT_803dd0c8 = (float)dVar14;
    if (*(int *)(param_3 + 0x98) == 0) {
      dVar14 = (double)FLOAT_803defb0;
    }
    else {
      dVar14 = (double)FLOAT_803defb0;
      if (*(ushort *)(param_3 + 0xd8) != 0) {
        dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xb2) * 8,
                                      *(ushort *)(param_3 + 0xd8) & 0xfff,param_4);
      }
    }
    FLOAT_803dd0c4 = (float)dVar14;
    FLOAT_803dd120 = FLOAT_803dd0cc;
    FLOAT_803dd11c = FLOAT_803dd0c8;
    FLOAT_803dd118 = (float)dVar14;
    DAT_803dd116 = *puVar7;
    DAT_803dd114 = 1;
    *(float *)(puVar7 + 6) = *(float *)(iVar13 + 8) + FLOAT_803dd0cc;
    *(float *)(puVar7 + 8) = *(float *)(iVar13 + 0xc) + FLOAT_803dd0c8;
    *(float *)(puVar7 + 10) = *(float *)(iVar13 + 0x10) + FLOAT_803dd0c4;
    uVar1 = *(ushort *)(param_3 + 0xde);
    if (uVar1 != 0) {
      if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xb8) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      if (*(char *)(param_3 + 0x7b) == '\0') {
        *(float *)(param_3 + 0x10) = (float)dVar14;
      }
      else {
        if (dVar14 < (double)FLOAT_803df040) {
          dVar14 = (double)FLOAT_803df040;
        }
        if ((double)FLOAT_803df048 < dVar14) {
          dVar14 = (double)FLOAT_803df044;
        }
        DAT_803dd088 = 1;
        FLOAT_803dd0d0 = (float)dVar14;
      }
    }
    if (((*(ushort *)(param_3 + 0x6e) & 0x20) != 0) &&
       (uVar1 = *(ushort *)(param_3 + 200), uVar1 != 0)) {
      if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xa2) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      if (dVar14 < (double)FLOAT_803defb0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      if ((double)FLOAT_803df04c < dVar14) {
        dVar14 = (double)FLOAT_803df04c;
      }
      *(char *)(iVar10 + 0x36) = (char)(int)dVar14;
    }
    uVar1 = *(ushort *)(param_3 + 0xca);
    if (uVar1 != 0) {
      if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xa4) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      (**(code **)(*DAT_803dca58 + 0x28))((double)(float)((double)FLOAT_803deffc * dVar14));
    }
    if (((*(ushort *)(param_3 + 0x6e) & 0x10) != 0) &&
       (uVar1 = *(ushort *)(param_3 + 0xcc), uVar1 != 0)) {
      if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xa6) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      *(float *)(iVar10 + 8) = (float)(dVar14 * (double)*(float *)(*(int *)(iVar10 + 0x50) + 4));
    }
    if (((*(ushort *)(param_3 + 0x6e) & 8) != 0) &&
       (psVar4 = (short *)FUN_800395d8(iVar10,0), psVar4 != (short *)0x0)) {
      uVar1 = *(ushort *)(param_3 + 0xc4);
      if (uVar1 == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0x9e) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      *psVar4 = *(short *)(param_3 + 0x116) + (short)(int)((double)FLOAT_803df03c * dVar14);
      uVar1 = *(ushort *)(param_3 + 0xc6);
      if (uVar1 == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xa0) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      psVar4[1] = *(short *)(param_3 + 0x114) + (short)(int)((double)FLOAT_803df03c * dVar14);
      uVar1 = *(ushort *)(param_3 + 0xc2);
      if (uVar1 == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0x9c) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      psVar4[2] = (short)(int)((double)FLOAT_803df03c * dVar14);
      if ((*(ushort *)(param_3 + 0x6e) & 0x400) != 0) {
        uVar12 = (uint)(*(byte *)(param_3 + 0x136) >> 4);
        puVar5 = (undefined4 *)FUN_800394a0();
        if (uVar12 == 0) {
          uVar12 = 9;
        }
        if (psVar4 != (short *)0x0) {
          for (iVar13 = 1; puVar5 = puVar5 + 1, iVar13 < (int)uVar12; iVar13 = iVar13 + 1) {
            psVar6 = (short *)FUN_800395d8(iVar10,*puVar5);
            if (psVar6 != (short *)0x0) {
              psVar6[1] = psVar4[1];
              *psVar6 = *psVar4;
              psVar6[2] = psVar4[2];
            }
          }
        }
      }
    }
    if (((*(ushort *)(param_3 + 0x6e) & 0x200) != 0) &&
       (puVar7 = (undefined2 *)FUN_800395d8(iVar10,1), puVar7 != (undefined2 *)0x0)) {
      uVar1 = *(ushort *)(param_3 + 0xe4);
      if (uVar1 == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else if (*(int *)(param_3 + 0x98) == 0) {
        dVar14 = (double)FLOAT_803defb0;
      }
      else {
        dVar14 = (double)FLOAT_803defb0;
        if (uVar1 != 0) {
          dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xbe) * 8,
                                        uVar1 & 0xfff,param_4);
        }
      }
      *puVar7 = (short)(int)((double)FLOAT_803df03c * dVar14);
    }
    if ((*(ushort *)(param_3 + 0x6e) & 0x40) != 0) {
      iVar13 = FUN_800394ac(iVar10,1,0);
      iVar3 = FUN_800394ac(iVar10,0,0);
      if ((iVar13 != 0) || (iVar3 != 0)) {
        uVar1 = *(ushort *)(param_3 + 0xe0);
        if (uVar1 == 0) {
          dVar14 = (double)FLOAT_803defb0;
        }
        else if (*(int *)(param_3 + 0x98) == 0) {
          dVar14 = (double)FLOAT_803defb0;
        }
        else {
          dVar14 = (double)FLOAT_803defb0;
          if (uVar1 != 0) {
            dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xba) * 8,
                                          uVar1 & 0xfff,param_4);
          }
        }
        sVar2 = (short)(int)((double)FLOAT_803df004 * dVar14);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 8) = sVar2;
        }
        if (iVar3 != 0) {
          *(short *)(iVar3 + 8) = -sVar2;
        }
        uVar1 = *(ushort *)(param_3 + 0xe2);
        if (uVar1 == 0) {
          dVar14 = (double)FLOAT_803defb0;
        }
        else if (*(int *)(param_3 + 0x98) == 0) {
          dVar14 = (double)FLOAT_803defb0;
        }
        else {
          dVar14 = (double)FLOAT_803defb0;
          if (uVar1 != 0) {
            dVar14 = (double)FUN_80082bf0(*(int *)(param_3 + 0x98) + *(short *)(param_3 + 0xbc) * 8,
                                          uVar1 & 0xfff,param_4);
          }
        }
        sVar2 = -(short)(int)((double)FLOAT_803df004 * dVar14);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 10) = sVar2;
        }
        if (iVar3 != 0) {
          *(short *)(iVar3 + 10) = sVar2;
        }
      }
      piVar8 = (int *)FUN_800394ac(iVar10,5,0);
      piVar9 = (int *)FUN_800394ac(iVar10,4,0);
      if (piVar8 != (int *)0x0) {
        *piVar8 = (int)(short)(ushort)*(byte *)(param_3 + 0x8d) << 8;
      }
      if (piVar9 != (int *)0x0) {
        *piVar9 = (int)(short)(ushort)*(byte *)(param_3 + 0x8e) << 8;
      }
    }
  }
  FUN_8028611c();
  return;
}

