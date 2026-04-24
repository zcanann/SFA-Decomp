// Function: FUN_8019cd98
// Entry: 8019cd98
// Size: 1300 bytes

/* WARNING: Removing unreachable block (ram,0x8019d28c) */

void FUN_8019cd98(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  undefined4 uVar12;
  undefined8 in_f31;
  double dVar13;
  int local_48 [2];
  double local_40;
  double local_38;
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar4 = (short *)FUN_802860dc();
  piVar9 = *(int **)(psVar4 + 0x5c);
  iVar10 = *(int *)(psVar4 + 0x26);
  if ((*(byte *)(piVar9 + 0x5d) >> 6 & 1) == 0) {
    local_38 = (double)CONCAT44(0x43300000,*(byte *)(psVar4 + 0x1b) ^ 0x80000000);
    iVar3 = (int)-(FLOAT_803e41bc * FLOAT_803db414 - (float)(local_38 - DOUBLE_803e41c0));
    local_40 = (double)(longlong)iVar3;
    if ((piVar9[3] != -1) && (iVar5 = FUN_8001ffb4(), iVar5 != 0)) {
      *(byte *)(piVar9 + 0x5d) = *(byte *)(piVar9 + 0x5d) & 0xbf | 0x40;
    }
  }
  else {
    local_40 = (double)CONCAT44(0x43300000,*(byte *)(psVar4 + 0x1b) ^ 0x80000000);
    iVar3 = (int)(FLOAT_803e41bc * FLOAT_803db414 + (float)(local_40 - DOUBLE_803e41c0));
    local_38 = (double)(longlong)iVar3;
    if ((piVar9[3] != -1) && (iVar5 = FUN_8001ffb4(), iVar5 == 0)) {
      *(byte *)(piVar9 + 0x5d) = *(byte *)(piVar9 + 0x5d) & 0xbf;
    }
  }
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (0xff < iVar3) {
    iVar3 = 0xff;
  }
  *(char *)(psVar4 + 0x1b) = (char)iVar3;
  iVar3 = FUN_8001ffb4(0x57);
  if (((iVar3 != 0) || (10 < *piVar9)) && ((*(byte *)(piVar9 + 0x5d) >> 6 & 1) != 0)) {
    iVar3 = piVar9[5];
    piVar9[5] = iVar3 + 1;
    if ((iVar3 < 0x3c) && (iVar3 = FUN_8001ffb4(piVar9[1]), iVar3 == 0)) {
      iVar10 = (uint)DAT_803db410 * 100 * piVar9[5] * piVar9[5];
      iVar10 = iVar10 / 0x3c + (iVar10 >> 0x1f);
      *psVar4 = *psVar4 - ((short)iVar10 - (short)(iVar10 >> 0x1f));
      FUN_8002b884(psVar4,0);
    }
    else {
      FUN_8002b884(psVar4,1);
      iVar3 = FUN_8001ffb4(piVar9[2]);
      *psVar4 = *psVar4 - (ushort)DAT_803db410 * 0xb6 * ((short)(iVar3 << 2) + 0xe);
      local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x1a) ^ 0x80000000);
      dVar13 = (double)(float)(local_38 - DOUBLE_803e41c0);
      iVar10 = FUN_8002b9ec(DOUBLE_803e41c0);
      iVar5 = FUN_8001ffb4(piVar9[1]);
      if (iVar5 == 0) {
        if (*(char *)(piVar9 + 0x5d) < '\0') {
          FUN_8000a518(0xbd,0);
          *(byte *)(piVar9 + 0x5d) = *(byte *)(piVar9 + 0x5d) & 0x7f;
        }
        if ((*(byte *)(piVar9 + 10) & 0xe0) != 0) {
          FUN_80296220((double)FLOAT_803e416c,iVar10);
          if ((*(byte *)(piVar9 + 10) & 0xe) != 0) {
            *(byte *)(piVar9 + 10) = *(byte *)(piVar9 + 10) | 2;
          }
          piVar9[9] = (int)FLOAT_803e416c;
          *(undefined *)((int)piVar9 + 0x29) = 0;
          *(byte *)(piVar9 + 10) = *(byte *)(piVar9 + 10) & 0xe;
        }
      }
      else {
        if (-1 < (char)*(byte *)(piVar9 + 0x5d)) {
          *(byte *)(piVar9 + 0x5d) = *(byte *)(piVar9 + 0x5d) & 0x7f | 0x80;
          FUN_8000a518(0xbd,1);
        }
        if (iVar10 != 0) {
          FUN_8019c784(dVar13,(double)(float)piVar9[0x5c],psVar4,iVar10,piVar9 + 6,iVar3,1,*piVar9);
        }
      }
      piVar6 = (int *)FUN_80036f50(0x16,local_48);
      local_48[0] = local_48[0] + 1;
      if (0xe < local_48[0]) {
        local_48[0] = 0xe;
      }
      piVar9[0x11] = -1;
      piVar9[0x17] = -1;
      piVar9[0x1d] = -1;
      piVar9[0x23] = -1;
      piVar9[0x29] = -1;
      piVar9[0x2f] = -1;
      piVar9[0x35] = -1;
      piVar9[0x3b] = -1;
      piVar9[0x41] = -1;
      piVar9[0x47] = -1;
      piVar9[0x4d] = -1;
      piVar9[0x53] = -1;
      piVar7 = piVar9 + 0x4e;
      iVar10 = 1;
      do {
        piVar7[0xb] = -1;
        piVar7 = piVar7 + 6;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
      for (iVar10 = 1; fVar2 = FLOAT_803e416c, fVar1 = FLOAT_803e4168, iVar10 < local_48[0];
          iVar10 = iVar10 + 1) {
        iVar5 = -1;
        iVar8 = 1;
        iVar11 = 0xd;
        piVar7 = piVar9;
        do {
          if (piVar7[0xc] == *piVar6) {
            iVar5 = iVar8;
          }
          iVar8 = iVar8 + 1;
          iVar11 = iVar11 + -1;
          piVar7 = piVar7 + 6;
        } while (iVar11 != 0);
        if (iVar5 == -1) {
          iVar8 = 1;
          while (iVar8 < 0xe) {
            iVar11 = iVar8;
            if (piVar9[iVar8 * 6 + 6] == 0) {
              *(undefined *)(piVar9 + iVar8 * 6 + 10) = 0;
              *(byte *)(piVar9 + iVar8 * 6 + 10) = *(byte *)(piVar9 + iVar8 * 6 + 10) & 0xe;
              piVar9[iVar8 * 6 + 7] = (int)fVar1;
              piVar9[iVar8 * 6 + 9] = (int)fVar2;
              piVar9[iVar8 * 6 + 8] = (int)fVar2;
              piVar9[iVar8 * 6 + 6] = 0;
              *(undefined *)((int)piVar9 + iVar8 * 0x18 + 0x29) = 0;
              iVar11 = 2000;
              iVar5 = iVar8;
            }
            iVar8 = iVar11 + 1;
          }
          if (iVar5 == -1) goto LAB_8019d28c;
          piVar9[iVar5 * 6 + 6] = *piVar6;
        }
        piVar9[iVar5 * 6 + 0xb] = iVar5;
        iVar8 = *piVar6;
        if ((*(ushort *)(iVar8 + 0xb0) & 0x1000) == 0) {
          if (iVar8 != 0) {
            piVar6 = piVar6 + 1;
            FUN_8019c784(dVar13,(double)(float)piVar9[0x5c],psVar4,iVar8,piVar9 + iVar5 * 6 + 6,
                         iVar3,0,*piVar9);
          }
        }
        else {
          piVar6 = piVar6 + 1;
        }
      }
      iVar10 = 0xd;
      do {
        if (piVar9[0x11] == -1) {
          piVar9[0xc] = 0;
        }
        iVar10 = iVar10 + -1;
        piVar9 = piVar9 + 6;
      } while (iVar10 != 0);
    }
  }
LAB_8019d28c:
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  FUN_80286128();
  return;
}

