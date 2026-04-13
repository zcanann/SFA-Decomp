// Function: FUN_80034dd4
// Entry: 80034dd4
// Size: 1736 bytes

/* WARNING: Removing unreachable block (ram,0x8003547c) */
/* WARNING: Removing unreachable block (ram,0x80034de4) */

void FUN_80034dd4(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int *piVar2;
  float *pfVar3;
  undefined4 *puVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  float fVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int *piVar16;
  double dVar17;
  undefined4 uStack_f28;
  undefined4 auStack_f24 [51];
  int aiStack_e58 [918];
  
  iVar1 = FUN_80286820();
  piVar2 = (int *)FUN_8002e1f4(&uStack_f28,auStack_f24);
  DAT_80341b9c = FLOAT_803df5e0;
  DAT_80341b98 = FLOAT_803df5e0;
  DAT_80341558 = &DAT_80341b98;
  iVar12 = 1;
  puVar4 = &DAT_80341ba4;
  piVar16 = &DAT_8034155c;
  piVar5 = piVar16;
  iVar7 = iVar12;
  if (0 < iVar1) {
    do {
      iVar6 = *piVar2;
      puVar8 = *(undefined4 **)(iVar6 + 0x54);
      iVar12 = iVar7;
      if (puVar8 != (undefined4 *)0x0) {
        if ((((*(ushort *)(puVar8 + 0x18) & 3) != 0) && (*(char *)((int)puVar8 + 0x62) != '\b')) &&
           (iVar7 < 400)) {
          *piVar5 = (int)puVar4;
          *(int *)(*piVar5 + 8) = iVar6;
          *(float *)(*piVar5 + 4) = *(float *)(iVar6 + 0x18) - (float)puVar8[0xe];
          puVar4 = puVar4 + 3;
          piVar5 = piVar5 + 1;
          iVar12 = iVar7 + 1;
          *(&DAT_80341558)[iVar7] = *(float *)(iVar6 + 0x18) + (float)puVar8[0xe];
        }
        *(ushort *)(puVar8 + 0x18) = *(ushort *)(puVar8 + 0x18) & 0xfff7;
        *(undefined *)((int)puVar8 + 0xad) = 0;
        *(undefined *)(puVar8 + 0x2b) = 0xff;
        *puVar8 = 0;
        iVar7 = *(int *)(iVar6 + 200);
        if ((iVar7 != 0) && (*(short *)(iVar7 + 0x44) == 0x2d)) {
          puVar8 = *(undefined4 **)(iVar7 + 0x54);
          *(ushort *)(puVar8 + 0x18) = *(ushort *)(puVar8 + 0x18) & 0xfff7;
          *(undefined *)((int)puVar8 + 0xad) = 0;
          *(undefined *)(puVar8 + 0x2b) = 0xff;
          *puVar8 = 0;
        }
      }
      piVar2 = piVar2 + 1;
      iVar1 = iVar1 + -1;
      iVar7 = iVar12;
    } while (iVar1 != 0);
  }
  FUN_800323e0(-0x7fcbeaa8,iVar12);
  iVar7 = 1;
  iVar1 = 1;
  piVar5 = piVar16;
  do {
    if (iVar12 <= iVar1) {
      piVar5 = piVar16;
      for (iVar7 = 1; iVar7 < iVar12; iVar7 = iVar7 + 1) {
        iVar1 = *(int *)(*piVar5 + 8);
        if (((*(ushort *)(*(int *)(iVar1 + 0x54) + 0x60) & 0x200) != 0) &&
           (FUN_800349a8(), *(int *)(iVar1 + 200) != 0)) {
          FUN_800349a8();
        }
        piVar5 = piVar5 + 1;
      }
      for (iVar7 = 1; iVar7 < iVar12; iVar7 = iVar7 + 1) {
        iVar1 = *(int *)(*piVar16 + 8);
        iVar6 = *(int *)(iVar1 + 0x54);
        *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar1 + 0xc);
        *(undefined4 *)(iVar6 + 0x14) = *(undefined4 *)(iVar1 + 0x10);
        *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar1 + 0x14);
        if (*(int *)(iVar1 + 0x30) == 0) {
          *(undefined4 *)(iVar6 + 0x1c) = *(undefined4 *)(iVar1 + 0xc);
          *(undefined4 *)(iVar6 + 0x20) = *(undefined4 *)(iVar1 + 0x10);
          *(undefined4 *)(iVar6 + 0x24) = *(undefined4 *)(iVar1 + 0x14);
        }
        else {
          FUN_8000e0c0((double)*(float *)(iVar6 + 0x10),(double)*(float *)(iVar6 + 0x14),
                       (double)*(float *)(iVar6 + 0x18),(float *)(iVar6 + 0x1c),
                       (float *)(iVar6 + 0x20),(float *)(iVar6 + 0x24),*(int *)(iVar1 + 0x30));
        }
        *(undefined *)(iVar6 + 0xae) = 0;
        *(ushort *)(iVar6 + 0x60) = *(ushort *)(iVar6 + 0x60) & 0xdfff;
        if ((((*(char *)(iVar6 + 0x71) != '\0') || ((*(ushort *)(iVar6 + 0x60) & 8) != 0)) &&
            ((*(ushort *)(iVar6 + 0x60) & 0x40) == 0)) &&
           ((*(ushort *)(iVar6 + 0x60) & 0x4000) == 0)) {
          *(float *)(iVar1 + 0x24) =
               FLOAT_803dc078 * (*(float *)(iVar1 + 0xc) - *(float *)(iVar1 + 0x80));
          *(float *)(iVar1 + 0x2c) =
               FLOAT_803dc078 * (*(float *)(iVar1 + 0x14) - *(float *)(iVar1 + 0x88));
        }
        piVar16 = piVar16 + 1;
      }
      DAT_802cb978 = 0;
      DAT_802cb97c = 0;
      DAT_802cb980 = 0;
      DAT_802cb984 = 0;
      DAT_802cb988 = 0;
      FUN_8028686c();
      return;
    }
    iVar15 = *(int *)(*piVar5 + 8);
    iVar14 = *(int *)(iVar15 + 0x54);
    iVar6 = *(int *)(iVar15 + 200);
    if ((iVar6 != 0) &&
       ((*(int *)(iVar6 + 0x54) == 0 || ((*(ushort *)(*(int *)(iVar6 + 0x54) + 0x60) & 1) == 0)))) {
      iVar6 = 0;
    }
    if ((*(ushort *)(iVar14 + 0x60) & 4) != 0) {
      puVar4 = &DAT_80341558 + iVar7;
      for (; (*(float *)*puVar4 < *(float *)(*piVar5 + 4) && (iVar7 < iVar12)); iVar7 = iVar7 + 1) {
        puVar4 = puVar4 + 1;
      }
      iVar9 = iVar7 << 2;
      iVar13 = iVar7;
      while (iVar13 < iVar12) {
        pfVar3 = *(float **)((int)&DAT_80341558 + iVar9);
        if (*(float *)*piVar5 <= pfVar3[1]) break;
        if (((float *)*piVar5)[1] <= *pfVar3) {
          fVar11 = pfVar3[2];
          iVar10 = *(int *)((int)fVar11 + 0x54);
          if ((iVar1 != iVar13) && (*(float *)(iVar15 + 0x30) != fVar11)) {
            dVar17 = (double)(*(float *)(iVar15 + 0x20) - *(float *)((int)fVar11 + 0x20));
            if (dVar17 <= (double)FLOAT_803df590) {
              dVar17 = -dVar17;
            }
            if (dVar17 < (double)(*(float *)(iVar14 + 0x2c) + *(float *)(iVar10 + 0x2c))) {
              dVar17 = (double)(*(float *)(iVar15 + 0x1c) - *(float *)((int)fVar11 + 0x1c));
              if (dVar17 <= (double)FLOAT_803df590) {
                dVar17 = -dVar17;
              }
              if ((((dVar17 < (double)(float)((double)*(float *)(iVar14 + 0x28) +
                                             (double)*(float *)(iVar10 + 0x28))) &&
                   ((*(ushort *)(iVar14 + 0x60) & 0x40) == 0)) &&
                  ((*(ushort *)(iVar10 + 0x60) & 0x40) == 0)) &&
                 ((((*(ushort *)(iVar10 + 0x60) & 4) == 0 || (iVar13 <= iVar1)) &&
                  (((*(byte *)(*(int *)(iVar15 + 0x50) + 0x71) & *(byte *)(iVar10 + 0xb5)) != 0 &&
                   ((*(byte *)(*(int *)((int)fVar11 + 0x50) + 0x71) & *(byte *)(iVar14 + 0xb5)) != 0
                   )))))) {
                if ((*(byte *)(iVar10 + 0x62) & 0x20) == 0) {
                  if ((*(byte *)(iVar14 + 0x62) & 0x20) == 0) {
                    if ((*(byte *)(iVar14 + 0x62) == 0x10) || (*(byte *)(iVar10 + 0x62) == 0x10)) {
                      if ((*(char *)(iVar14 + 0x6a) != '\0') || (*(char *)(iVar10 + 0x6a) != '\0'))
                      {
                        FUN_800326b8((double)*(float *)(iVar14 + 0x28),param_2,param_3,param_4,
                                     param_5,param_6,param_7,param_8,iVar15,fVar11,iVar15,0,1,
                                     0xffffffff,0,in_r10);
                      }
                    }
                    else if ((*(char *)(iVar14 + 0x6a) != '\0') ||
                            (*(char *)(iVar10 + 0x6a) != '\0')) {
                      FUN_8003407c();
                    }
                  }
                  else {
                    in_r10 = 0;
                    FUN_8003454c(iVar15,fVar11,aiStack_e58);
                  }
                }
                else {
                  in_r10 = 0;
                  FUN_8003454c(fVar11,iVar15,aiStack_e58);
                }
              }
            }
            if (dVar17 < (double)(*(float *)(iVar14 + 0x34) + *(float *)(iVar10 + 0x34))) {
              param_2 = (double)(*(float *)(iVar15 + 0x1c) - *(float *)((int)fVar11 + 0x1c));
              if (param_2 <= (double)FLOAT_803df590) {
                param_2 = -param_2;
              }
              if ((((param_2 < (double)(*(float *)(iVar14 + 0x30) + *(float *)(iVar10 + 0x30))) &&
                   ((*(ushort *)(iVar14 + 0x60) & 0x100) == 0)) &&
                  ((*(ushort *)(iVar10 + 0x60) & 0x100) == 0)) &&
                 (((*(byte *)(iVar14 + 0xb4) & *(byte *)(iVar10 + 0xb5)) != 0 &&
                  (((*(byte *)(iVar10 + 0xb4) & 0x80) != 0 ||
                   ((*(byte *)(iVar10 + 0xb4) & *(byte *)(iVar14 + 0xb5)) != 0)))))) {
                iVar10 = *(int *)((int)fVar11 + 200);
                if ((iVar10 != 0) &&
                   ((*(int *)(iVar10 + 0x54) == 0 ||
                    ((*(ushort *)(*(int *)(iVar10 + 0x54) + 0x60) & 1) == 0)))) {
                  iVar10 = 0;
                }
                FUN_800334c4((double)FLOAT_803dc074,param_2,param_3,param_4,param_5,param_6,param_7,
                             param_8,iVar15,fVar11,iVar6,iVar10);
              }
            }
          }
          iVar13 = iVar13 + 1;
          iVar9 = iVar9 + 4;
        }
        else {
          iVar13 = iVar13 + 1;
          iVar9 = iVar9 + 4;
        }
      }
    }
    piVar5 = piVar5 + 1;
    iVar1 = iVar1 + 1;
  } while( true );
}

