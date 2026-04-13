// Function: FUN_801024e8
// Entry: 801024e8
// Size: 1652 bytes

/* WARNING: Removing unreachable block (ram,0x80102b38) */
/* WARNING: Removing unreachable block (ram,0x801024f8) */

void FUN_801024e8(void)

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
  double dVar12;
  
  psVar6 = DAT_803de134;
  iVar11 = *(int *)(DAT_803de19c + 0x124);
  if (DAT_803de134 == (short *)0x0) {
    return;
  }
  iVar8 = FUN_80134f70();
  if (iVar8 != 0) {
    return;
  }
  if ((DAT_803de130 != '\0') && (DAT_803de130 = '\0', iVar11 != 0)) {
    cVar2 = *(char *)(DAT_803de19c + 0x138);
    if (cVar2 == '\x01') {
      FUN_8000bb38(0,0x3ff);
      FUN_80098230((double)FLOAT_803e22ac,psVar6,2);
    }
    else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
      FUN_8000bb38(0,0x402);
      FUN_80098230((double)FLOAT_803e22ac,psVar6,3);
    }
    else if (cVar2 != '\b') {
      FUN_8000bb38(0,0x288);
      FUN_80098230((double)FLOAT_803e22ac,psVar6,1);
    }
  }
  if (iVar11 != 0) {
    *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 4;
    uVar9 = FUN_80014e9c(0);
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
    else if ((bVar1) && (iVar8 = FUN_8012ee7c(), iVar8 == 0)) {
      FUN_8000bb38(0,0x287);
    }
  }
  if (DAT_803de142 == '\0') {
    if (FLOAT_803e22b0 < *(float *)(psVar6 + 0x4c)) {
      FUN_8002fb40((double)FLOAT_803e22f0,(double)FLOAT_803dc074);
    }
    else if (iVar11 == 0) {
      *(undefined4 *)(DAT_803de19c + 0x128) = 0;
    }
    else {
      *(int *)(DAT_803de19c + 0x128) = iVar11;
      *(byte *)(DAT_803de19c + 0x138) =
           *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
      DAT_803de142 = '\x03';
      DAT_803de130 = '\x01';
    }
  }
  else if ((*(int *)(DAT_803de19c + 0x128) == iVar11) ||
          (*(float *)(psVar6 + 0x4c) < FLOAT_803e22ac)) {
    FUN_8002fb40((double)FLOAT_803e22f4,(double)FLOAT_803dc074);
  }
  else {
    DAT_803de142 = '\0';
    if (iVar11 == 0) {
      cVar2 = *(char *)(DAT_803de19c + 0x138);
      if (cVar2 == '\x01') {
        FUN_8000bb38(0,0x400);
      }
      else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
        FUN_8000bb38(0,0x401);
      }
      else if (cVar2 != '\b') {
        FUN_8000bb38(0,0x289);
      }
    }
    else {
      FUN_800303fc((double)FLOAT_803e22b0,(int)psVar6);
    }
  }
  iVar11 = FUN_80037ad4(*(int *)(DAT_803de19c + 0x128));
  if (iVar11 == 0) {
    *(undefined4 *)(DAT_803de19c + 0x128) = 0;
  }
  if ((DAT_803de142 != '\x03') || (*(int *)(DAT_803de19c + 0x128) == 0)) goto LAB_80102ab4;
  if ((*(byte *)(*(int *)(DAT_803de19c + 0x128) + 0xaf) & 0x10) == 0) {
    *(byte *)(DAT_803de19c + 0x141) = *(byte *)(DAT_803de19c + 0x141) & 0xdf;
  }
  else {
    *(byte *)(DAT_803de19c + 0x141) = *(byte *)(DAT_803de19c + 0x141) | 0x20;
  }
  iVar11 = *(int *)(DAT_803de19c + 0x128);
  sVar3 = *(short *)(iVar11 + 0x46);
  if (sVar3 == 0x49f) {
LAB_80102994:
    dVar12 = FUN_8018375c(iVar11);
  }
  else {
    if (sVar3 < 0x49f) {
      if (sVar3 != 0x281) {
        if (sVar3 < 0x281) {
          if (sVar3 != 0x13a) {
            if (sVar3 < 0x13a) {
              if (sVar3 == 0x31) {
                dVar12 = (double)FLOAT_803e22ac;
                goto LAB_801029e0;
              }
              if (sVar3 < 0x31) {
                if (sVar3 != 0x11) goto LAB_801029ac;
              }
              else if (sVar3 != 0xd8) goto LAB_801029ac;
            }
            else if ((sVar3 != 0x25d) && ((0x25c < sVar3 || (sVar3 != 0x251)))) goto LAB_801029ac;
          }
        }
        else if (sVar3 != 0x3fe) {
          if (sVar3 < 0x3fe) {
            if (sVar3 == 0x3de) goto LAB_80102994;
            if ((0x3dd < sVar3) || (sVar3 != 0x369)) goto LAB_801029ac;
          }
          else if (sVar3 < 0x457) {
            if (sVar3 != 0x427) goto LAB_801029ac;
          }
          else if (0x458 < sVar3) goto LAB_801029ac;
        }
      }
    }
    else if (sVar3 != 0x613) {
      if (sVar3 < 0x613) {
        if (sVar3 != 0x58b) {
          if (sVar3 < 0x58b) {
            if ((sVar3 != 0x4d7) && ((0x4d6 < sVar3 || (sVar3 != 0x4ac)))) {
LAB_801029ac:
              iVar8 = FUN_80111fb0(iVar11);
              if (iVar8 == 0) {
                dVar12 = (double)FLOAT_803e22ac;
              }
              else {
                dVar12 = (double)(**(code **)(*DAT_803dd738 + 0x60))(iVar11);
              }
              goto LAB_801029e0;
            }
          }
          else if ((sVar3 != 0x5e1) && (((0x5e0 < sVar3 || (0x5b9 < sVar3)) || (sVar3 < 0x5b7))))
          goto LAB_801029ac;
        }
      }
      else if (sVar3 != 0x842) {
        if (sVar3 < 0x842) {
          if (sVar3 < 0x6a2) {
            if (sVar3 != 0x642) goto LAB_801029ac;
          }
          else if (0x6a5 < sVar3) goto LAB_801029ac;
        }
        else if ((sVar3 != 0x851) && ((0x850 < sVar3 || (sVar3 != 0x84b)))) goto LAB_801029ac;
      }
    }
    dVar12 = FUN_8014ca48(iVar11);
  }
LAB_801029e0:
  if (((double)FLOAT_803e22b0 < dVar12) ||
     ((double)*(float *)(DAT_803de19c + 0x134) <= (double)FLOAT_803e22b0)) {
    if (((double)FLOAT_803e22b4 < dVar12) ||
       ((double)*(float *)(DAT_803de19c + 0x134) <= (double)FLOAT_803e22b4)) {
      if (((double)FLOAT_803e22b8 < dVar12) ||
         ((double)*(float *)(DAT_803de19c + 0x134) <= (double)FLOAT_803e22b8)) {
        if ((dVar12 <= (double)FLOAT_803e22bc) &&
           ((double)FLOAT_803e22bc < (double)*(float *)(DAT_803de19c + 0x134))) {
          FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
        }
      }
      else {
        FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
      }
    }
    else {
      FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
    }
  }
  else {
    FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
  }
  *(float *)(DAT_803de19c + 0x134) = (float)dVar12;
LAB_80102ab4:
  fVar4 = FLOAT_803e22f8 * *(float *)(psVar6 + 0x4c);
  fVar5 = FLOAT_803e22b0;
  if ((FLOAT_803e22b0 <= fVar4) && (fVar5 = fVar4, FLOAT_803e22f8 < fVar4)) {
    fVar5 = FLOAT_803e22f8;
  }
  *(char *)(psVar6 + 0x1b) = (char)(int)fVar5;
  DAT_803de140 = 0x400;
  *psVar6 = (short)(int)(FLOAT_803e22fc * FLOAT_803dc074 +
                        (float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) -
                               DOUBLE_803e22d0));
  return;
}

