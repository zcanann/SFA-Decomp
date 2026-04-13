// Function: FUN_801ad3d4
// Entry: 801ad3d4
// Size: 1124 bytes

/* WARNING: Removing unreachable block (ram,0x801ad818) */
/* WARNING: Removing unreachable block (ram,0x801ad5b0) */
/* WARNING: Removing unreachable block (ram,0x801ad3e4) */

void FUN_801ad3d4(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  ushort uVar5;
  bool bVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int *piVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 local_30;
  
  uVar7 = FUN_8028683c();
  piVar13 = *(int **)(uVar7 + 0xb8);
  iVar12 = *(int *)(uVar7 + 0x54);
  iVar10 = *(int *)(uVar7 + 100);
  iVar11 = *(int *)(uVar7 + 0x4c);
  if (DAT_803de7c0 == 0) {
    DAT_803de7c0 = FUN_80013ee8(0x5b);
  }
  if (*(char *)((int)piVar13 + 0xe) == '\0') {
    dVar15 = FUN_801ad2b0(uVar7);
    piVar13[1] = (int)(float)dVar15;
    if ((*(char *)((int)piVar13 + 0xe) != '\0') && (iVar10 != 0)) {
      *(int *)(iVar10 + 0x24) = piVar13[1];
      FUN_80062a48();
    }
  }
  else {
    if (iVar10 != 0) {
      fVar3 = (*(float *)(uVar7 + 0x10) - (float)piVar13[1]) /
              ((float)piVar13[2] - (float)piVar13[1]);
      fVar4 = FLOAT_803e53a0;
      if ((fVar3 <= FLOAT_803e53a0) && (fVar4 = fVar3, fVar3 < FLOAT_803e5380)) {
        fVar4 = FLOAT_803e5380;
      }
      dVar15 = (double)(FLOAT_803e53a0 - fVar4);
      iVar8 = FUN_8002bac4();
      if (iVar8 == 0) {
        dVar14 = (double)FLOAT_803e53a4;
      }
      else {
        dVar16 = (double)FUN_800217c8((float *)(uVar7 + 0x18),(float *)(iVar8 + 0x18));
        dVar14 = (double)FLOAT_803e53a4;
        if ((dVar16 <= dVar14) && (dVar14 = dVar16, dVar16 < (double)FLOAT_803e53a8)) {
          dVar14 = (double)FLOAT_803e53a8;
        }
      }
      param_3 = (double)(FLOAT_803e53a0 - (float)(dVar14 - (double)FLOAT_803e53a8) / FLOAT_803e53ac)
      ;
      param_2 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(uVar7 + 0x37)) -
                                DOUBLE_803e5390) / FLOAT_803e53b4);
      *(char *)(iVar10 + 0x40) =
           (char)(int)(param_2 *
                      (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                       (int)((double)FLOAT_803e53b0
                                                                            * dVar15) + 0x40U ^
                                                                       0x80000000) - DOUBLE_803e53c0
                                                     ) * param_3));
    }
    uVar9 = (uint)*(short *)(iVar11 + 0x1c);
    if ((uVar9 == 0xffffffff) || (uVar9 = FUN_80020078(uVar9), uVar9 != 0)) {
      bVar1 = *(byte *)(piVar13 + 3);
      if (bVar1 == 2) {
        *(undefined4 *)(iVar12 + 0x48) = 0x10;
        *(undefined4 *)(iVar12 + 0x4c) = 0x10;
        *(undefined *)(iVar12 + 0x6f) = 1;
        *(undefined *)(iVar12 + 0x6e) = 0xd;
      }
      else if (bVar1 < 2) {
        if (bVar1 == 0) {
          iVar10 = FUN_8002bac4();
          if (iVar10 == 0) {
            bVar6 = false;
          }
          else {
            iVar8 = *(int *)(uVar7 + 0x4c);
            dVar15 = (double)FUN_80021754((float *)(uVar7 + 0x18),(float *)(iVar10 + 0x18));
            param_4 = (double)(*(float *)(uVar7 + 0x10) - *(float *)(iVar10 + 0x10));
            if (param_4 < (double)FLOAT_803e5380) {
              param_4 = (double)FLOAT_803e5380;
            }
            param_3 = (double)FLOAT_803e5384;
            local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar8 + 0x1a));
            param_2 = DOUBLE_803e5390;
            if (((double)(float)(param_3 * (double)(float)(local_30 - DOUBLE_803e5390)) <= dVar15)
               || ((double)FLOAT_803e5388 <= param_4)) {
              bVar6 = false;
            }
            else {
              bVar6 = true;
            }
          }
          if ((bVar6) &&
             (sVar2 = *(short *)(piVar13 + 4), uVar5 = (ushort)DAT_803dc070,
             *(ushort *)(piVar13 + 4) = sVar2 - uVar5, (short)(sVar2 - uVar5) < 1)) {
            *(undefined *)(piVar13 + 3) = 1;
          }
        }
        else {
          if (*(char *)((int)piVar13 + 0xd) == '\0') {
            *(undefined *)((int)piVar13 + 0xd) = 1;
            *(float *)(uVar7 + 0x28) = FLOAT_803e5380;
            if (*(short *)(uVar7 + 0x46) == 0x67) {
              FUN_8000bb38(uVar7,0x155);
            }
            FUN_8000bb38(uVar7,0xa5);
            *(ushort *)(iVar12 + 0x60) = *(ushort *)(iVar12 + 0x60) | 1;
          }
          *(undefined4 *)(iVar12 + 0x48) = 0x10;
          *(undefined4 *)(iVar12 + 0x4c) = 0x10;
          *(undefined *)(iVar12 + 0x6f) = 1;
          *(undefined *)(iVar12 + 0x6e) = 0xd;
          *(float *)(uVar7 + 0x28) = FLOAT_803e53b8 * FLOAT_803dc074 + *(float *)(uVar7 + 0x28);
          *(float *)(uVar7 + 0x10) =
               *(float *)(uVar7 + 0x28) * FLOAT_803dc074 + *(float *)(uVar7 + 0x10);
          param_3 = (double)(float)piVar13[1];
          param_2 = (double)*(float *)(*piVar13 + 8);
          if (*(float *)(uVar7 + 0x10) < (float)(param_3 + param_2)) {
            *(float *)(uVar7 + 0x10) = (float)(param_2 * (double)*(float *)(uVar7 + 8) + param_3);
            *(undefined *)(piVar13 + 3) = 2;
            if (*(int *)(*piVar13 + 4) != 0) {
              FUN_8000bb38(uVar7,(ushort)*(int *)(*piVar13 + 4));
            }
          }
        }
      }
      if (*(int *)(iVar12 + 0x50) != 0) {
        *(ushort *)(iVar12 + 0x60) = *(ushort *)(iVar12 + 0x60) & 0xfffe;
        *(undefined *)(piVar13 + 3) = 3;
        FUN_8000b7dc(uVar7,8);
        if (*(short *)(uVar7 + 0x46) == 0x67) {
          FUN_8000bb38(uVar7,0x156);
        }
        else {
          FUN_8000bb38(uVar7,0x3bb);
          local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar11 + 0x1b));
          FUN_8009adfc((double)(float)(local_30 - DOUBLE_803e5390),param_2,param_3,param_4,param_5,
                       param_6,param_7,param_8,uVar7,1,1,0,1,1,1,1);
        }
      }
      fVar3 = FLOAT_803e5380;
      *(float *)(uVar7 + 0x24) = FLOAT_803e5380;
      *(float *)(uVar7 + 0x2c) = fVar3;
    }
  }
  FUN_80286888();
  return;
}

