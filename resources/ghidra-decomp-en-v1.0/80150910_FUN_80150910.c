// Function: FUN_80150910
// Entry: 80150910
// Size: 1484 bytes

void FUN_80150910(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  char cVar5;
  int *piVar6;
  uint uVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined *puVar10;
  int iVar11;
  double dVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_802860d8();
  psVar4 = (short *)((ulonglong)uVar13 >> 0x20);
  piVar6 = (int *)uVar13;
  iVar11 = *piVar6;
  uVar7 = (uint)*(byte *)((int)piVar6 + 0x33b);
  puVar10 = (&PTR_DAT_8031f170)[uVar7 * 10];
  puVar9 = (&PTR_DAT_8031f16c)[uVar7 * 10];
  puVar8 = (&PTR_DAT_8031f188)[uVar7 * 10];
  if ((uVar7 == 5) && ((piVar6[0xb7] & 0x800000U) != 0)) {
    FUN_800200e8(0x1c8,1);
  }
  FUN_8015039c(psVar4,piVar6);
  fVar1 = FLOAT_803e2740;
  if ((((float)piVar6[0xca] != FLOAT_803e2740) && (*(short *)(piVar6 + 0xce) != 0)) &&
     (piVar6[0xca] = (int)((float)piVar6[0xca] - FLOAT_803db414), (float)piVar6[0xca] <= fVar1)) {
    piVar6[0xca] = (int)fVar1;
    piVar6[0xb7] = piVar6[0xb7] | 0x40000000;
    *(ushort *)(piVar6 + 0xce) = (ushort)(byte)puVar8[(uint)*(ushort *)(piVar6 + 0xce) * 0x10 + 10];
  }
  cVar5 = FUN_8014ffb4(psVar4,piVar6,0);
  fVar1 = FLOAT_803e2740;
  if (cVar5 == '\0') {
    if (*(char *)((int)piVar6 + 0x33d) != '\0') {
      if ((piVar6[0xb7] & 0x40000000U) != 0) {
        *(float *)(psVar4 + 0x16) = FLOAT_803e2740;
        *(float *)(psVar4 + 0x14) = fVar1;
        *(float *)(psVar4 + 0x12) = fVar1;
        iVar3 = (uint)*(byte *)((int)piVar6 + 0x33d) * 0xc;
        FUN_8014d08c((double)*(float *)(puVar10 + iVar3),psVar4,piVar6,puVar10[iVar3 + 8],0,
                     *(uint *)(puVar10 + iVar3 + 4) & 0xff);
        FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                       (uint)(byte)puVar10[(uint)*(byte *)((int)piVar6 + 0x33d) *
                                                           0xc + 8] * 4),psVar4);
        *(undefined *)((int)piVar6 + 0x33d) =
             puVar10[(uint)*(byte *)((int)piVar6 + 0x33d) * 0xc + 9];
        *(undefined *)((int)piVar6 + 0x33e) = 0;
      }
      if (*(char *)((int)piVar6 + 0x33e) == '\0') goto LAB_80150ec4;
    }
    if (((piVar6[0xb7] & 0x80000000U) != 0) && (*(char *)((int)piVar6 + 0x33d) == '\0')) {
      FUN_8014c064(psVar4);
    }
    if ((piVar6[0xb7] & 0x2000U) == 0) {
      if ((*(char *)((int)piVar6 + 0x33d) == '\0') && ((piVar6[0xb7] & 0x40000000U) != 0)) {
        uVar7 = FUN_800221a0(1,puVar10[8]);
        if (*(ushort *)(piVar6 + 0xce) == 0) {
          iVar11 = (uVar7 & 0xff) * 0xc;
          if ((psVar4[0x50] != (ushort)(byte)puVar10[iVar11 + 8]) ||
             ((byte)puVar10[iVar11 + 8] != 0)) {
            *(undefined *)((int)piVar6 + 0x2f2) = 0;
            *(undefined *)((int)piVar6 + 0x2f3) = 0;
            *(undefined *)(piVar6 + 0xbd) = 0;
            FUN_8014d08c((double)*(float *)(puVar10 + iVar11),psVar4,piVar6,puVar10[iVar11 + 8],0,3)
            ;
            FUN_80030304((double)*(float *)(&DAT_8031dd30 + (uint)(byte)puVar10[iVar11 + 8] * 4),
                         psVar4);
          }
        }
        else {
          *(char *)((int)piVar6 + 0x2f2) =
               (char)*(undefined4 *)(puVar8 + (uint)*(ushort *)(piVar6 + 0xce) * 0x10 + 0xc);
          iVar11 = (uint)*(ushort *)(piVar6 + 0xce) * 0x10;
          FUN_8014d08c((double)*(float *)(puVar8 + iVar11),psVar4,piVar6,puVar8[iVar11 + 8],0,
                       *(uint *)(puVar8 + iVar11 + 4) & 0xff);
          FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                         (uint)(byte)puVar8[(uint)*(ushort *)(piVar6 + 0xce) * 0x10
                                                            + 8] * 4),psVar4);
          *(ushort *)(piVar6 + 0xce) =
               (ushort)(byte)puVar8[(uint)*(ushort *)(piVar6 + 0xce) * 0x10 + 9];
        }
      }
    }
    else {
      fVar1 = *(float *)(iVar11 + 0x68) - *(float *)(psVar4 + 6);
      fVar2 = *(float *)(iVar11 + 0x70) - *(float *)(psVar4 + 10);
      dVar12 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
      if ((double)FLOAT_803e2778 < dVar12) {
        dVar12 = (double)FLOAT_803e2778;
      }
      piVar6[0xc4] = (int)((float)((double)FLOAT_803e2778 - dVar12) * FLOAT_803e277c *
                          (float)piVar6[0xbf]);
      if ((float)piVar6[0xc4] < FLOAT_803e2780) {
        piVar6[0xc4] = (int)FLOAT_803e2780;
      }
      iVar3 = FUN_80010320((double)(float)piVar6[0xc4],iVar11);
      if (((iVar3 != 0) || (*(int *)(iVar11 + 0x10) != 0)) &&
         (cVar5 = (**(code **)(*DAT_803dca9c + 0x90))(iVar11), cVar5 != '\0')) {
        FUN_8014c064(psVar4);
      }
      uVar7 = FUN_800217c0((double)*(float *)(iVar11 + 0x74),(double)*(float *)(iVar11 + 0x7c));
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       ((uVar7 & 0xffff) + 0x8000) - ((int)*psVar4 & 0xffffU) ^
                                       0x80000000) - DOUBLE_803e2758);
      if (FLOAT_803e2788 < fVar1) {
        fVar1 = FLOAT_803e2784 + fVar1;
      }
      if (fVar1 < FLOAT_803e2790) {
        fVar1 = FLOAT_803e278c + fVar1;
      }
      if (fVar1 < FLOAT_803e2740) {
        fVar1 = -fVar1;
      }
      piVar6[0xc2] = (int)((((float)piVar6[0xbf] - (float)piVar6[0xc4]) / FLOAT_803e274c) *
                          (FLOAT_803e2748 - fVar1 / FLOAT_803e278c));
      if ((float)piVar6[0xc2] < FLOAT_803e2754) {
        piVar6[0xc2] = (int)FLOAT_803e2754;
      }
      if (((piVar6[0xb7] & 0x40000000U) != 0) && (*(char *)((int)piVar6 + 0x33d) == '\0')) {
        if (*(ushort *)(piVar6 + 0xce) == 0) {
          if ((float)piVar6[0xc4] <= FLOAT_803e2794) {
            *(undefined *)((int)piVar6 + 0x2f2) = 0;
            *(undefined *)((int)piVar6 + 0x2f3) = 0;
            *(undefined *)(piVar6 + 0xbd) = 0;
            *(undefined *)((int)piVar6 + 0x323) = 1;
            piVar6[0xc2] = (int)FLOAT_803e279c;
            FUN_80030334((double)FLOAT_803e2740,psVar4,puVar9[8],0);
            piVar6[0xc4] = (int)FLOAT_803e2740;
          }
          else {
            *(undefined *)((int)piVar6 + 0x2f2) = 0;
            *(undefined *)((int)piVar6 + 0x2f3) = 0;
            *(undefined *)(piVar6 + 0xbd) = 0;
            if ((float)piVar6[0xc4] <= FLOAT_803e2798) {
              *(undefined *)((int)piVar6 + 0x323) = 1;
              FUN_80030334((double)FLOAT_803e2740,psVar4,puVar9[0x14],0);
            }
            else {
              *(undefined *)((int)piVar6 + 0x323) = 1;
              FUN_80030334((double)FLOAT_803e2740,psVar4,puVar9[0x20],0);
            }
          }
        }
        else {
          iVar3 = (uint)*(ushort *)(piVar6 + 0xce) * 0x10;
          FUN_8014d08c((double)*(float *)(puVar8 + iVar3),psVar4,piVar6,puVar8[iVar3 + 8],0,
                       *(uint *)(puVar8 + iVar3 + 4) & 0xff);
          FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                         (uint)(byte)puVar8[(uint)*(ushort *)(piVar6 + 0xce) * 0x10
                                                            + 8] * 4),psVar4);
          *(ushort *)(piVar6 + 0xce) =
               (ushort)(byte)puVar8[(uint)*(ushort *)(piVar6 + 0xce) * 0x10 + 9];
        }
      }
      FUN_8014cf7c((double)*(float *)(iVar11 + 0x68),(double)*(float *)(iVar11 + 0x70),psVar4,piVar6
                   ,0xf,0);
    }
  }
LAB_80150ec4:
  FUN_80286124();
  return;
}

