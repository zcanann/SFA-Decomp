// Function: FUN_8010224c
// Entry: 8010224c
// Size: 1652 bytes

/* WARNING: Removing unreachable block (ram,0x8010289c) */

void FUN_8010224c(void)

{
  bool bVar1;
  char cVar2;
  short sVar3;
  float fVar4;
  float fVar5;
  short *psVar6;
  byte bVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  undefined4 uVar12;
  double dVar13;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  psVar6 = DAT_803dd4bc;
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar11 = *(int *)(DAT_803dd524 + 0x124);
  if ((DAT_803dd4bc == (short *)0x0) || (iVar8 = FUN_80134be8(), iVar8 != 0)) goto LAB_8010289c;
  if ((DAT_803dd4b8 != '\0') && (DAT_803dd4b8 = '\0', iVar11 != 0)) {
    cVar2 = *(char *)(DAT_803dd524 + 0x138);
    if (cVar2 == '\x01') {
      FUN_8000bb18(0,0x3ff);
      FUN_80097fa4((double)FLOAT_803e162c,psVar6,2);
    }
    else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
      FUN_8000bb18(0,0x402);
      FUN_80097fa4((double)FLOAT_803e162c,psVar6,3);
    }
    else if (cVar2 != '\b') {
      FUN_8000bb18(0,0x288);
      FUN_80097fa4((double)FLOAT_803e162c,psVar6,1);
    }
  }
  if (iVar11 != 0) {
    *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 4;
    uVar9 = FUN_80014e70(0);
    uVar10 = 0x100;
    bVar7 = *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
    if ((bVar7 == 4) || (bVar7 == 9)) {
      uVar10 = 0x900;
    }
    bVar1 = (uVar9 & uVar10) != 0;
    if ((*(byte *)(iVar11 + 0xaf) & 0x10) == 0) {
      if (bVar1) {
        *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 1;
      }
    }
    else if ((bVar1) && (iVar8 = FUN_8012ea44(), iVar8 == 0)) {
      FUN_8000bb18(0,0x287);
    }
  }
  if (DAT_803dd4ca == '\0') {
    if (FLOAT_803e1630 < *(float *)(psVar6 + 0x4c)) {
      FUN_8002fa48((double)FLOAT_803e1670,(double)FLOAT_803db414,psVar6,0);
    }
    else if (iVar11 == 0) {
      *(undefined4 *)(DAT_803dd524 + 0x128) = 0;
    }
    else {
      *(int *)(DAT_803dd524 + 0x128) = iVar11;
      *(byte *)(DAT_803dd524 + 0x138) =
           *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
      DAT_803dd4ca = '\x03';
      DAT_803dd4b8 = '\x01';
    }
  }
  else if ((*(int *)(DAT_803dd524 + 0x128) == iVar11) ||
          (*(float *)(psVar6 + 0x4c) < FLOAT_803e162c)) {
    FUN_8002fa48((double)FLOAT_803e1674,(double)FLOAT_803db414,psVar6,0);
  }
  else {
    DAT_803dd4ca = '\0';
    if (iVar11 == 0) {
      cVar2 = *(char *)(DAT_803dd524 + 0x138);
      if (cVar2 == '\x01') {
        FUN_8000bb18(0,0x400);
      }
      else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
        FUN_8000bb18(0,0x401);
      }
      else if (cVar2 != '\b') {
        FUN_8000bb18(0,0x289);
      }
    }
    else {
      FUN_80030304((double)FLOAT_803e1630,psVar6);
    }
  }
  iVar11 = FUN_800379dc(*(undefined4 *)(DAT_803dd524 + 0x128));
  if (iVar11 == 0) {
    *(undefined4 *)(DAT_803dd524 + 0x128) = 0;
  }
  if ((DAT_803dd4ca == '\x03') && (*(int *)(DAT_803dd524 + 0x128) != 0)) {
    if ((*(byte *)(*(int *)(DAT_803dd524 + 0x128) + 0xaf) & 0x10) == 0) {
      *(byte *)(DAT_803dd524 + 0x141) = *(byte *)(DAT_803dd524 + 0x141) & 0xdf;
    }
    else {
      *(byte *)(DAT_803dd524 + 0x141) = *(byte *)(DAT_803dd524 + 0x141) | 0x20;
    }
    iVar11 = *(int *)(DAT_803dd524 + 0x128);
    sVar3 = *(short *)(iVar11 + 0x46);
    if (sVar3 == 0x49f) {
LAB_801026f8:
      dVar13 = (double)FUN_80183204(iVar11);
    }
    else {
      if (sVar3 < 0x49f) {
        if (sVar3 != 0x281) {
          if (sVar3 < 0x281) {
            if (sVar3 != 0x13a) {
              if (sVar3 < 0x13a) {
                if (sVar3 == 0x31) {
                  dVar13 = (double)FLOAT_803e162c;
                  goto LAB_80102744;
                }
                if (sVar3 < 0x31) {
                  if (sVar3 != 0x11) goto LAB_80102710;
                }
                else if (sVar3 != 0xd8) goto LAB_80102710;
              }
              else if ((sVar3 != 0x25d) && ((0x25c < sVar3 || (sVar3 != 0x251)))) goto LAB_80102710;
            }
          }
          else if (sVar3 != 0x3fe) {
            if (sVar3 < 0x3fe) {
              if (sVar3 == 0x3de) goto LAB_801026f8;
              if ((0x3dd < sVar3) || (sVar3 != 0x369)) goto LAB_80102710;
            }
            else if (sVar3 < 0x457) {
              if (sVar3 != 0x427) goto LAB_80102710;
            }
            else if (0x458 < sVar3) goto LAB_80102710;
          }
        }
      }
      else if (sVar3 != 0x613) {
        if (sVar3 < 0x613) {
          if (sVar3 != 0x58b) {
            if (sVar3 < 0x58b) {
              if ((sVar3 != 0x4d7) && ((0x4d6 < sVar3 || (sVar3 != 0x4ac)))) {
LAB_80102710:
                iVar8 = FUN_80111d14(iVar11);
                if (iVar8 == 0) {
                  dVar13 = (double)FLOAT_803e162c;
                }
                else {
                  dVar13 = (double)(**(code **)(*DAT_803dcab8 + 0x60))(iVar11);
                }
                goto LAB_80102744;
              }
            }
            else if ((sVar3 != 0x5e1) && (((0x5e0 < sVar3 || (0x5b9 < sVar3)) || (sVar3 < 0x5b7))))
            goto LAB_80102710;
          }
        }
        else if (sVar3 != 0x842) {
          if (sVar3 < 0x842) {
            if (sVar3 < 0x6a2) {
              if (sVar3 != 0x642) goto LAB_80102710;
            }
            else if (0x6a5 < sVar3) goto LAB_80102710;
          }
          else if ((sVar3 != 0x851) && ((0x850 < sVar3 || (sVar3 != 0x84b)))) goto LAB_80102710;
        }
      }
      dVar13 = (double)FUN_8014c5d0(iVar11);
    }
LAB_80102744:
    if (((double)FLOAT_803e1630 < dVar13) ||
       ((double)*(float *)(DAT_803dd524 + 0x134) <= (double)FLOAT_803e1630)) {
      if (((double)FLOAT_803e1634 < dVar13) ||
         ((double)*(float *)(DAT_803dd524 + 0x134) <= (double)FLOAT_803e1634)) {
        if (((double)FLOAT_803e1638 < dVar13) ||
           ((double)*(float *)(DAT_803dd524 + 0x134) <= (double)FLOAT_803e1638)) {
          if ((dVar13 <= (double)FLOAT_803e163c) &&
             ((double)FLOAT_803e163c < (double)*(float *)(DAT_803dd524 + 0x134))) {
            FUN_80097fa4((double)FLOAT_803e162c,psVar6,4);
          }
        }
        else {
          FUN_80097fa4((double)FLOAT_803e162c,psVar6,4);
        }
      }
      else {
        FUN_80097fa4((double)FLOAT_803e162c,psVar6,4);
      }
    }
    else {
      FUN_80097fa4((double)FLOAT_803e162c,psVar6,4);
    }
    *(float *)(DAT_803dd524 + 0x134) = (float)dVar13;
  }
  fVar4 = FLOAT_803e1678 * *(float *)(psVar6 + 0x4c);
  fVar5 = FLOAT_803e1630;
  if ((FLOAT_803e1630 <= fVar4) && (fVar5 = fVar4, FLOAT_803e1678 < fVar4)) {
    fVar5 = FLOAT_803e1678;
  }
  *(char *)(psVar6 + 0x1b) = (char)(int)fVar5;
  DAT_803dd4c8 = 0x400;
  *psVar6 = (short)(int)(FLOAT_803e167c * FLOAT_803db414 +
                        (float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) -
                               DOUBLE_803e1650));
LAB_8010289c:
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  return;
}

