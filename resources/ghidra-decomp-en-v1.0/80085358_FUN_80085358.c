// Function: FUN_80085358
// Entry: 80085358
// Size: 2012 bytes

void FUN_80085358(undefined4 param_1,undefined4 param_2,char **param_3,uint param_4)

{
  float fVar1;
  char cVar2;
  ushort uVar3;
  short sVar4;
  float fVar5;
  undefined uVar6;
  byte bVar9;
  int iVar7;
  uint uVar8;
  int iVar10;
  int iVar11;
  int *piVar12;
  bool bVar13;
  int iVar14;
  uint uVar15;
  short sVar16;
  short sVar17;
  char *pcVar18;
  int *piVar19;
  undefined8 uVar20;
  
  uVar20 = FUN_802860d4();
  cVar2 = DAT_803dd113;
  iVar11 = (int)((ulonglong)uVar20 >> 0x20);
  piVar12 = (int *)uVar20;
  pcVar18 = *param_3;
  bVar9 = (byte)param_4 & 2;
  if ((param_4 & 1) == 0) {
    bVar9 = 1;
  }
  piVar19 = *(int **)(iVar11 + 0xb8);
  iVar10 = *piVar19;
  if (*piVar19 == 0) {
    iVar10 = iVar11;
  }
  switch(*pcVar18) {
  case '\x01':
    if ((param_4 & 8) == 0) {
      if ((*(char *)((int)piVar19 + 0x7b) == '\0') ||
         ((&DAT_8039a358)[*(char *)((int)piVar19 + 0x57)] == '\0')) {
        *(char *)(piVar19 + 0x1e) = '\x01' - *(char *)(piVar19 + 0x1e);
      }
      else {
        *(undefined *)(piVar19 + 0x1e) = 0;
      }
    }
    break;
  case '\x02':
    if ((param_4 & 8) == 0) {
      *(ushort *)(piVar19 + 0x1b) = *(ushort *)(pcVar18 + 2) & 0xfff;
      if ((*(short *)(iVar10 + 0x44) == 1) && (*(short *)(piVar19 + 0x1b) < 4)) {
        *(short *)(piVar19 + 0x1b) = *(short *)(piVar19 + 0x1b) + 0x531;
      }
      *(byte *)(piVar19 + 0x23) = (byte)((uint)(int)*(short *)(pcVar18 + 2) >> 8) & 0xf0;
      if (piVar12 != (int *)0x0) {
        iVar7 = piVar12[0xb];
        if (*(short *)(iVar10 + 0xa0) == *(short *)(piVar19 + 0x1b)) {
          if (*(char *)(iVar7 + 0x60) == '\0') {
            bVar13 = true;
          }
          else {
            bVar13 = false;
          }
        }
        else {
          bVar13 = true;
        }
        if ((((bVar9 != 0) && (bVar13)) && ((*(ushort *)((int)piVar19 + 0x6e) & 4) != 0)) &&
           (piVar12 != (int *)0x0)) {
          *(float *)(iVar7 + 4) = *(float *)(iVar10 + 0x98) * *(float *)(iVar7 + 0x14);
          uVar3 = *(ushort *)((int)piVar19 + 0xd6);
          if (uVar3 != 0) {
            if ((piVar19[0x26] != 0) && (uVar3 != 0)) {
              FUN_80082bf0(piVar19[0x26] + *(short *)(piVar19 + 0x2c) * 8,uVar3 & 0xfff,
                           *(short *)(piVar19 + 0x16) + -1);
            }
          }
          if (*(short *)(iVar10 + 0x44) == 1) {
            iVar7 = *(int *)(*(int *)(iVar10 + 0x7c) + *(char *)(iVar10 + 0xad) * 4);
            iVar14 = *(int *)(iVar7 + 0x2c);
            *(undefined2 *)(iVar14 + 100) = 0xffff;
            *(undefined2 *)(iVar14 + 0x5a) = 0;
            *(undefined2 *)(iVar14 + 0x5c) = 0;
            iVar7 = *(int *)(iVar7 + 0x30);
            if (iVar7 != 0) {
              *(undefined2 *)(iVar7 + 100) = 0xffff;
              *(undefined2 *)(iVar7 + 0x58) = 0;
              *(undefined2 *)(iVar7 + 0x5a) = 0;
              *(undefined2 *)(iVar7 + 0x5c) = 0;
            }
          }
          piVar19[8] = (int)FLOAT_803defc8;
          FUN_80030334((double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(piVar19 + 0x23))
                                       - DOUBLE_803defe0) * FLOAT_803df02c),iVar10,
                       (int)*(short *)(piVar19 + 0x1b),0);
        }
      }
    }
    break;
  case '\x03':
    if (((param_4 & 8) == 0) && ((param_4 & 4) == 0)) {
      iVar10 = FUN_80085dc4(iVar11,piVar19,*(undefined4 *)(iVar11 + 0x4c));
      *(undefined2 *)(iVar10 + 0xa2) = 0xffff;
    }
    break;
  case '\x04':
    if (((((param_4 & 8) == 0) && (bVar9 != 0)) && (piVar12 != (int *)0x0)) &&
       (*(char *)(*piVar12 + 0xf9) != '\0')) {
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       (uint)(int)*(short *)(pcVar18 + 2) >> 8 & 0xff ^ 0x80000000)
                     - DOUBLE_803defb8);
      fVar5 = FLOAT_803defc8;
      if (FLOAT_803defb0 != fVar1) {
        fVar5 = FLOAT_803defc8 / fVar1;
      }
      uVar8 = (int)*(short *)(pcVar18 + 2) & 0xff;
      if (uVar8 < 0xf) {
        FUN_800279cc((double)fVar5,piVar12,2,(int)*(char *)(piVar12[10] + 0x2d),uVar8 - 1,0);
      }
      else {
        FUN_800279cc((double)fVar5,piVar12,0,(int)*(char *)(piVar12[10] + 0xd),uVar8 - 1,0);
      }
    }
    break;
  case '\a':
    *(char *)((int)piVar19 + 0x7a) = '\x01' - *(char *)((int)piVar19 + 0x7a);
    break;
  case '\v':
    if (((bVar9 != 0) && (0 < *(short *)(pcVar18 + 2))) && (DAT_803dd0c0 < 0x14)) {
      (&DAT_8039944c)[DAT_803dd0c0 * 2] = pcVar18 + 4;
      (&DAT_80399452)[DAT_803dd0c0 * 4] = *(undefined2 *)(piVar19 + 0x16);
      iVar7 = DAT_803dd0c0 * 4;
      DAT_803dd0c0 = DAT_803dd0c0 + 1;
      (&DAT_80399450)[iVar7] = *(undefined2 *)(pcVar18 + 2);
    }
    *(short *)((int)piVar19 + 0x66) = *(short *)((int)piVar19 + 0x66) + *(short *)(pcVar18 + 2);
    break;
  case '\r':
    if ((((param_4 & 1) == 0) && (((uint)(int)*(short *)(pcVar18 + 2) >> 0xc & 0xf) != 8)) &&
       (DAT_803dd113 < 10)) {
      iVar7 = DAT_803dd113 * 8;
      *(int *)(&DAT_8039a5bc + iVar7) = iVar10;
      (&DAT_8039a5c2)[iVar7] = (byte)((uint)(int)*(short *)(pcVar18 + 2) >> 0xc) & 0xf;
      bVar9 = (&DAT_8039a5c2)[iVar7];
      if ((bVar9 == 0xb) || (bVar9 == 0xc)) {
        iVar7 = (int)DAT_803dd113;
        DAT_803dd113 = DAT_803dd113 + '\x01';
        *(undefined2 *)(&DAT_8039a5c0 + iVar7 * 8) = *(undefined2 *)(pcVar18 + 6);
      }
      else {
        DAT_803dd113 = cVar2 + '\x01';
        *(ushort *)(&DAT_8039a5c0 + iVar7) = *(ushort *)(pcVar18 + 2) & 0xfff;
      }
    }
    break;
  case '\x0e':
    if ((param_4 & 8) == 0) {
      (**(code **)(*DAT_803dca68 + 0x38))((int)*(short *)(pcVar18 + 2),0x14,0x8c,0);
    }
  }
  if ((param_4 & 1) == 0) {
    if ((DAT_803dd112 == '\0') && (DAT_803dd111 == '\0')) {
      cVar2 = *pcVar18;
      if (cVar2 == '\r') {
        uVar8 = (uint)*(short *)(pcVar18 + 2);
        uVar6 = (undefined)*(short *)(pcVar18 + 2);
        switch(uVar8 >> 0xc & 0xf) {
        case 0:
          if ((((&DAT_80399e50)[*(char *)((int)piVar19 + 0x57)] & 0x20) != 0) &&
             ((iVar11 = (uVar8 & 0xfff) + 1, iVar11 == 0xd9 || (iVar11 == 0x92)))) {
            FUN_8000a518(iVar11,1);
          }
          break;
        case 2:
          FUN_80008cbc(iVar10,iVar10,uVar8 & 0xfff,0);
          break;
        case 6:
          if ((param_4 & 8) == 0) {
            FUN_800552e8(uVar8 & 0xfff,0);
          }
          break;
        case 7:
          break;
        case 8:
          if ((param_4 & 8) == 0) {
            *(undefined *)((int)piVar19 + 0x8d) = uVar6;
            *(undefined *)((int)piVar19 + 0x8e) = *(undefined *)((int)piVar19 + 0x8d);
          }
          break;
        case 0xe:
          if ((param_4 & 8) == 0) {
            *(undefined *)((int)piVar19 + 0x8d) = uVar6;
          }
          break;
        case 0xf:
          if ((param_4 & 8) == 0) {
            *(undefined *)((int)piVar19 + 0x8e) = uVar6;
          }
        }
      }
      else if (cVar2 < '\r') {
        if (((cVar2 == '\x06') && ((param_4 & 8) == 0)) &&
           ((((&DAT_80399e50)[*(char *)((int)piVar19 + 0x57)] & 0x20) != 0 &&
            ((&DAT_8039a564)[*(char *)((int)piVar19 + 0x57)] != '\x03')))) {
          uVar8 = (uint)*(short *)(pcVar18 + 2);
          if ((uVar8 >> 0xc & 0xf) == 0xf) {
            FUN_8000bb18(iVar11,uVar8 & 0xfff);
            *(undefined2 *)((int)piVar19 + 0x36) = 0xffff;
            *(ushort *)((int)piVar19 + 0x3e) = *(ushort *)(pcVar18 + 2) & 0xfff;
          }
          else {
            FUN_8000bb18(iVar11,uVar8 & 0xfff);
          }
        }
      }
      else if ((((cVar2 == '\x0f') && ((param_4 & 8) == 0)) &&
               (((&DAT_80399e50)[*(char *)((int)piVar19 + 0x57)] & 0x20) != 0)) &&
              ((&DAT_8039a564)[*(char *)((int)piVar19 + 0x57)] != '\x03')) {
        if (((uint)(int)*(short *)(pcVar18 + 2) >> 0xc & 0xf) == 0xf) {
          uVar8 = 3;
        }
        else {
          sVar16 = 0x7fff;
          if (*(short *)(piVar19 + 0xc) < 0x7fff) {
            sVar16 = *(short *)(piVar19 + 0xc);
          }
          sVar4 = *(short *)((int)piVar19 + 0x32);
          sVar17 = sVar16;
          if (sVar4 < sVar16) {
            sVar17 = sVar4;
          }
          uVar8 = (uint)(sVar4 < sVar16);
          if (*(short *)(piVar19 + 0xd) < sVar17) {
            uVar8 = 2;
          }
        }
        iVar10 = uVar8 * 2;
        if (0 < *(short *)((int)piVar19 + iVar10 + 0x30)) {
          FUN_8000db90(iVar11,*(undefined2 *)((int)piVar19 + iVar10 + 0x38));
        }
        pcVar18[1] = pcVar18[5];
        pcVar18[4] = 'c';
        *(undefined2 *)((int)piVar19 + iVar10 + 0x30) = *(undefined2 *)(pcVar18 + 6);
        *(ushort *)((int)piVar19 + iVar10 + 0x38) = *(ushort *)(pcVar18 + 2) & 0xfff;
        FUN_8000dcbc(iVar11,*(undefined2 *)((int)piVar19 + iVar10 + 0x38));
      }
    }
    else if (*pcVar18 == '\r') {
      uVar15 = (uint)*(short *)(pcVar18 + 2);
      uVar8 = uVar15 >> 0xc & 0xf;
      if (uVar8 != 5) {
        if (uVar8 < 5) {
          if (uVar8 == 2) {
            FUN_80008cbc(iVar10,iVar10,uVar15 & 0xfff,0);
          }
        }
        else if (uVar8 < 7) {
          FUN_800552e8(uVar15 & 0xfff,0);
        }
      }
    }
  }
  FUN_80286120(0);
  return;
}

