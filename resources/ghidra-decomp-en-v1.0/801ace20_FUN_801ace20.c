// Function: FUN_801ace20
// Entry: 801ace20
// Size: 1124 bytes

/* WARNING: Removing unreachable block (ram,0x801acffc) */
/* WARNING: Removing unreachable block (ram,0x801ad264) */

void FUN_801ace20(void)

{
  byte bVar1;
  short sVar2;
  float fVar3;
  ushort uVar4;
  bool bVar5;
  float fVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int *piVar12;
  undefined4 uVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f31;
  double local_30;
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar7 = FUN_802860d8();
  piVar12 = *(int **)(iVar7 + 0xb8);
  iVar11 = *(int *)(iVar7 + 0x54);
  iVar9 = *(int *)(iVar7 + 100);
  iVar10 = *(int *)(iVar7 + 0x4c);
  if (DAT_803ddb40 == 0) {
    DAT_803ddb40 = FUN_80013ec8(0x5b,1);
  }
  if (*(char *)((int)piVar12 + 0xe) == '\0') {
    dVar15 = (double)FUN_801accfc(iVar7);
    piVar12[1] = (int)(float)dVar15;
    if ((*(char *)((int)piVar12 + 0xe) != '\0') && (iVar9 != 0)) {
      *(int *)(iVar9 + 0x24) = piVar12[1];
      FUN_800628cc(iVar7);
    }
  }
  else {
    if (iVar9 != 0) {
      fVar3 = (*(float *)(iVar7 + 0x10) - (float)piVar12[1]) /
              ((float)piVar12[2] - (float)piVar12[1]);
      fVar6 = FLOAT_803e4708;
      if ((fVar3 <= FLOAT_803e4708) && (fVar6 = fVar3, fVar3 < FLOAT_803e46e8)) {
        fVar6 = FLOAT_803e46e8;
      }
      dVar15 = (double)(FLOAT_803e4708 - fVar6);
      iVar8 = FUN_8002b9ec();
      if (iVar8 == 0) {
        dVar14 = (double)FLOAT_803e470c;
      }
      else {
        dVar16 = (double)FUN_80021704(iVar7 + 0x18,iVar8 + 0x18);
        dVar14 = (double)FLOAT_803e470c;
        if ((dVar16 <= dVar14) && (dVar14 = dVar16, dVar16 < (double)FLOAT_803e4710)) {
          dVar14 = (double)FLOAT_803e4710;
        }
      }
      *(char *)(iVar9 + 0x40) =
           (char)(int)(((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar7 + 0x37)) -
                               DOUBLE_803e46f8) / FLOAT_803e471c) *
                      (float)((double)CONCAT44(0x43300000,
                                               (int)((double)FLOAT_803e4718 * dVar15) + 0x40U ^
                                               0x80000000) - DOUBLE_803e4728) *
                      (FLOAT_803e4708 - (float)(dVar14 - (double)FLOAT_803e4710) / FLOAT_803e4714));
    }
    if ((*(short *)(iVar10 + 0x1c) == -1) || (iVar9 = FUN_8001ffb4(), iVar9 != 0)) {
      bVar1 = *(byte *)(piVar12 + 3);
      if (bVar1 == 2) {
        *(undefined4 *)(iVar11 + 0x48) = 0x10;
        *(undefined4 *)(iVar11 + 0x4c) = 0x10;
        *(undefined *)(iVar11 + 0x6f) = 1;
        *(undefined *)(iVar11 + 0x6e) = 0xd;
      }
      else if (bVar1 < 2) {
        if (bVar1 == 0) {
          iVar9 = FUN_8002b9ec();
          if (iVar9 == 0) {
            bVar5 = false;
          }
          else {
            iVar8 = *(int *)(iVar7 + 0x4c);
            dVar15 = (double)FUN_80021690(iVar7 + 0x18,iVar9 + 0x18);
            fVar3 = *(float *)(iVar7 + 0x10) - *(float *)(iVar9 + 0x10);
            if (fVar3 < FLOAT_803e46e8) {
              fVar3 = FLOAT_803e46e8;
            }
            local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar8 + 0x1a));
            if (((double)(FLOAT_803e46ec * (float)(local_30 - DOUBLE_803e46f8)) <= dVar15) ||
               (FLOAT_803e46f0 <= fVar3)) {
              bVar5 = false;
            }
            else {
              bVar5 = true;
            }
          }
          if ((bVar5) &&
             (sVar2 = *(short *)(piVar12 + 4), uVar4 = (ushort)DAT_803db410,
             *(ushort *)(piVar12 + 4) = sVar2 - uVar4, (short)(sVar2 - uVar4) < 1)) {
            *(undefined *)(piVar12 + 3) = 1;
          }
        }
        else {
          if (*(char *)((int)piVar12 + 0xd) == '\0') {
            *(undefined *)((int)piVar12 + 0xd) = 1;
            *(float *)(iVar7 + 0x28) = FLOAT_803e46e8;
            if (*(short *)(iVar7 + 0x46) == 0x67) {
              FUN_8000bb18(iVar7,0x155);
            }
            FUN_8000bb18(iVar7,0xa5);
            *(ushort *)(iVar11 + 0x60) = *(ushort *)(iVar11 + 0x60) | 1;
          }
          *(undefined4 *)(iVar11 + 0x48) = 0x10;
          *(undefined4 *)(iVar11 + 0x4c) = 0x10;
          *(undefined *)(iVar11 + 0x6f) = 1;
          *(undefined *)(iVar11 + 0x6e) = 0xd;
          *(float *)(iVar7 + 0x28) = FLOAT_803e4720 * FLOAT_803db414 + *(float *)(iVar7 + 0x28);
          *(float *)(iVar7 + 0x10) =
               *(float *)(iVar7 + 0x28) * FLOAT_803db414 + *(float *)(iVar7 + 0x10);
          if (*(float *)(iVar7 + 0x10) < (float)piVar12[1] + *(float *)(*piVar12 + 8)) {
            *(float *)(iVar7 + 0x10) =
                 *(float *)(*piVar12 + 8) * *(float *)(iVar7 + 8) + (float)piVar12[1];
            *(undefined *)(piVar12 + 3) = 2;
            if (*(uint *)(*piVar12 + 4) != 0) {
              FUN_8000bb18(iVar7,*(uint *)(*piVar12 + 4) & 0xffff);
            }
          }
        }
      }
      if (*(int *)(iVar11 + 0x50) != 0) {
        *(ushort *)(iVar11 + 0x60) = *(ushort *)(iVar11 + 0x60) & 0xfffe;
        *(undefined *)(piVar12 + 3) = 3;
        FUN_8000b7bc(iVar7,8);
        if (*(short *)(iVar7 + 0x46) == 0x67) {
          FUN_8000bb18(iVar7,0x156);
        }
        else {
          FUN_8000bb18(iVar7,0x3bb);
          local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar10 + 0x1b));
          FUN_8009ab70((double)(float)(local_30 - DOUBLE_803e46f8),iVar7,1,1,0,1,1,1,1);
        }
      }
      fVar3 = FLOAT_803e46e8;
      *(float *)(iVar7 + 0x24) = FLOAT_803e46e8;
      *(float *)(iVar7 + 0x2c) = fVar3;
    }
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286124();
  return;
}

