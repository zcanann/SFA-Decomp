// Function: FUN_801f1188
// Entry: 801f1188
// Size: 2376 bytes

/* WARNING: Removing unreachable block (ram,0x801f1aa8) */
/* WARNING: Removing unreachable block (ram,0x801f1aa0) */
/* WARNING: Removing unreachable block (ram,0x801f1a98) */
/* WARNING: Removing unreachable block (ram,0x801f1a90) */
/* WARNING: Removing unreachable block (ram,0x801f1a88) */
/* WARNING: Removing unreachable block (ram,0x801f1a80) */
/* WARNING: Removing unreachable block (ram,0x801f11c0) */
/* WARNING: Removing unreachable block (ram,0x801f11b8) */
/* WARNING: Removing unreachable block (ram,0x801f11b0) */
/* WARNING: Removing unreachable block (ram,0x801f11a8) */
/* WARNING: Removing unreachable block (ram,0x801f11a0) */
/* WARNING: Removing unreachable block (ram,0x801f1198) */

void FUN_801f1188(uint param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  char cVar4;
  ushort uVar5;
  uint uVar6;
  undefined2 uVar9;
  uint uVar7;
  undefined4 uVar8;
  undefined4 uVar10;
  undefined4 uVar11;
  int iVar12;
  undefined4 in_r10;
  int iVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  undefined8 uVar18;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  undefined8 local_78;
  
  iVar14 = *(int *)(param_1 + 0x4c);
  iVar13 = *(int *)(param_1 + 0xb8);
  *(ushort *)(iVar13 + 0x2c) = *(short *)(iVar13 + 0x2c) - (ushort)DAT_803dc070;
  uVar6 = FUN_80020078((int)*(short *)(iVar14 + 0x1e));
  if (uVar6 == 0) {
    if (*(short *)(iVar13 + 0x2c) < 0) {
      if (*(char *)(iVar13 + 0x25) == '\0') {
        cVar4 = *(char *)(iVar13 + 0x4e);
        if ((cVar4 == '\x03') || (cVar4 == '\x1e')) {
          *(undefined2 *)(iVar13 + 0x2c) = *(undefined2 *)(iVar13 + 0x30);
        }
        else {
          if ((cVar4 == '\0') && (*(short *)(iVar13 + 0x32) != -1)) {
            (**(code **)(*DAT_803dd6fc + 0x20))(iVar13 + 0x32);
          }
          *(undefined2 *)(iVar13 + 0x2c) = *(undefined2 *)(iVar13 + 0x30);
        }
        *(float *)(iVar13 + 0x1c) = FLOAT_803e69a8;
      }
      else {
        *(undefined2 *)(iVar13 + 0x2c) = 0x96;
      }
      *(undefined *)(iVar13 + 0x4d) = 0;
    }
    else if (*(short *)(iVar13 + 0x2c) < *(short *)(iVar13 + 0x2e)) {
      if (*(char *)(iVar13 + 0x4d) == '\0') {
        *(undefined *)(iVar13 + 0x4d) = 1;
        cVar4 = *(char *)(iVar13 + 0x4e);
        if (cVar4 == '\x01') {
          if (DAT_803de900 != (int *)0x0) {
            (**(code **)(*DAT_803de900 + 4))(param_1,2,0,0x10004,0xffffffff,0);
          }
        }
        else if ((cVar4 != '\x1e') && (cVar4 != '\0')) {
          (**(code **)(*DAT_803de900 + 4))(param_1,0,0,0x10004,0xffffffff,0);
        }
      }
      if (*(short *)(iVar13 + 0x2c) < 0x28) {
        if ((FLOAT_803e69a8 <= *(float *)(iVar13 + 0x1c)) && (*(char *)(iVar13 + 0x25) == '\0')) {
          *(float *)(iVar13 + 0x1c) = -(FLOAT_803e69ac * FLOAT_803dc074 - *(float *)(iVar13 + 0x1c))
          ;
        }
      }
      else if (*(short *)(iVar13 + 0x2c) < 0x8c) {
        if (*(char *)(iVar13 + 0x4d) == '\x01') {
          *(undefined *)(iVar13 + 0x4d) = 2;
          cVar4 = *(char *)(iVar13 + 0x4e);
          if (cVar4 == '\x01') {
            if (DAT_803de900 != (int *)0x0) {
              (**(code **)(*DAT_803de900 + 4))(param_1,3,0,0x10004,0xffffffff,0);
            }
          }
          else if (cVar4 == '\x1e') {
            if (DAT_803de900 != (int *)0x0) {
              uVar9 = (**(code **)(*DAT_803de900 + 4))(param_1,0x1e,0,0x10004,0xffffffff,0);
              *(undefined2 *)(iVar13 + 0x32) = uVar9;
            }
          }
          else if (cVar4 == '\0') {
            if ((DAT_803de900 != (int *)0x0) && (bVar1 = *(short *)(iVar13 + 0x32) == -1, bVar1)) {
              if (!bVar1) {
                (**(code **)(*DAT_803dd6fc + 0x20))(iVar13 + 0x32);
              }
              if (DAT_803de900 != (int *)0x0) {
                uVar9 = (**(code **)(*DAT_803de900 + 4))(param_1,0,0,0x10004,0xffffffff,0);
                *(undefined2 *)(iVar13 + 0x32) = uVar9;
              }
            }
          }
          else if (DAT_803de900 != (int *)0x0) {
            (**(code **)(*DAT_803de900 + 4))(param_1,1,0,0x10004,0xffffffff,0);
          }
        }
      }
      else if (*(float *)(iVar13 + 0x1c) <= FLOAT_803e69b0) {
        *(float *)(iVar13 + 0x1c) = FLOAT_803e69b4 * FLOAT_803dc074 + *(float *)(iVar13 + 0x1c);
      }
    }
  }
  else if ((*(char *)(iVar13 + 0x4e) == '\0') && (*(short *)(iVar13 + 0x32) != -1)) {
    (**(code **)(*DAT_803dd6fc + 0x20))(iVar13 + 0x32);
  }
  dVar22 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x1a) ^ 0x80000000)
                          - DOUBLE_803e69e8);
  dVar21 = (double)(float)(dVar22 * dVar22);
  dVar15 = (double)FUN_80294964();
  dVar16 = (double)FUN_802945e0();
  dVar19 = -(double)(float)((double)*(float *)(param_1 + 0xc) * dVar15 +
                           (double)(float)((double)*(float *)(param_1 + 0x14) * dVar16));
  uVar6 = FUN_8002bac4();
  *(byte *)(iVar13 + 0x27) = *(char *)(iVar13 + 0x27) - DAT_803dc070;
  if (*(char *)(iVar13 + 0x27) < '\x01') {
    *(undefined *)(iVar13 + 0x27) = 0;
  }
  else if ((*(char *)(iVar13 + 0x4e) == '\0') && (*(short *)(iVar13 + 0x32) != -1)) {
    (**(code **)(*DAT_803dd6fc + 0x20))(iVar13 + 0x32);
  }
  if (((FLOAT_803e69a8 <
        (float)(dVar19 + (double)(float)(dVar15 * (double)*(float *)(uVar6 + 0xc) +
                                        (double)(float)(dVar16 * (double)*(float *)(uVar6 + 0x14))))
       ) && (*(char *)(iVar13 + 0x4e) != '\x02')) || (*(char *)(iVar13 + 0x4e) == '\x1e')) {
    *(ushort *)(iVar13 + 0x2a) = *(short *)(iVar13 + 0x2a) - (ushort)DAT_803dc070;
    if (*(short *)(iVar13 + 0x2a) < 0) {
      *(undefined2 *)(iVar13 + 0x2a) = 0;
      *(undefined *)(iVar13 + 0x25) = 0;
    }
  }
  else {
    *(ushort *)(iVar13 + 0x2a) = *(short *)(iVar13 + 0x2a) + (ushort)DAT_803dc070;
    if (0x3c < *(short *)(iVar13 + 0x2a)) {
      *(undefined2 *)(iVar13 + 0x2a) = 0x3c;
      *(undefined *)(iVar13 + 0x25) = 1;
    }
  }
  if (*(char *)(iVar13 + 0x25) == '\0') {
    *(byte *)(iVar13 + 0x24) = *(byte *)(iVar13 + 0x4d) & 3;
  }
  else {
    *(undefined *)(iVar13 + 0x24) = 2;
  }
  uVar7 = FUN_80020078((int)*(short *)(iVar14 + 0x1e));
  if (uVar7 != 0) {
    *(undefined *)(iVar13 + 0x24) = 0;
  }
  if (*(char *)(iVar13 + 0x27) == '\0') {
    *(undefined2 *)(iVar13 + 0x28) = 0;
  }
  if (((uVar6 != 0) && (*(char *)(iVar13 + 0x27) == '\0')) && (*(char *)(iVar13 + 0x24) == '\x02'))
  {
    local_78 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar13 + 0x26) ^ 0x80000000);
    dVar20 = (double)(FLOAT_803e69c0 + (float)(local_78 - DOUBLE_803e69e8));
    dVar17 = (double)(*(float *)(uVar6 + 0x10) - *(float *)(param_1 + 0x10));
    if ((dVar17 < dVar20) && (-(double)(float)((double)FLOAT_803e69c4 + dVar20) < dVar17)) {
      fVar2 = (float)((double)*(float *)(uVar6 + 0xc) - (double)*(float *)(param_1 + 0xc));
      fVar3 = (float)((double)*(float *)(uVar6 + 0x14) - (double)*(float *)(param_1 + 0x14));
      if ((double)(fVar2 * fVar2 + fVar3 * fVar3) < dVar21) {
        dVar17 = (double)(float)(dVar19 + (double)(float)(dVar15 * (double)*(float *)(uVar6 + 0xc) +
                                                         (double)(float)(dVar16 * (double)*(float *)
                                                  (uVar6 + 0x14))));
        dVar21 = dVar17;
        if (dVar17 < (double)FLOAT_803e69a8) {
          dVar21 = -dVar17;
        }
        if ((double)FLOAT_803e69c8 < dVar21) {
          dVar21 = (double)FLOAT_803e69c8;
        }
        *(short *)(iVar13 + 0x28) =
             (short)(int)(FLOAT_803e69cc * (float)((double)FLOAT_803e69c8 - dVar21));
        if ((((double)FLOAT_803e69d0 <= dVar17) || (dVar17 <= (double)FLOAT_803e69d4)) &&
           (*(char *)(iVar13 + 0x4c) == '\x01')) {
          (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
          *(undefined *)(iVar13 + 0x4c) = 0;
        }
        if ((dVar17 < dVar20) && (-dVar20 < dVar17)) {
          iVar14 = FUN_80297300(uVar6);
          if ((iVar14 == 0x1d7) && (*(char *)(iVar13 + 0x4e) != '\x01')) {
            FUN_800201ac(0x468,1);
          }
          else {
            fVar2 = FLOAT_803e69dc;
            if ((float)(dVar19 + (double)(float)(dVar15 * (double)*(float *)(uVar6 + 0x80) +
                                                (double)(float)(dVar16 * (double)*(float *)(uVar6 + 
                                                  0x88)))) < FLOAT_803e69a8) {
              fVar2 = FLOAT_803e69d8;
            }
            dVar17 = (double)fVar2;
            dVar19 = (double)*(float *)(param_1 + 0x10);
            dVar21 = (double)*(float *)(uVar6 + 0x14);
            FUN_8000bb00((double)*(float *)(uVar6 + 0xc),dVar19,dVar21,param_1,0x1c9);
            if (*(short *)(*(int *)(uVar6 + 0xb8) + 0x81a) == 0) {
              uVar5 = 0x1f;
            }
            else {
              uVar5 = 0x23;
            }
            FUN_8000bb38(uVar6,uVar5);
            iVar14 = 0;
            do {
              uVar8 = FUN_8002bac4();
              uVar10 = 0xffffffff;
              uVar11 = 0;
              iVar12 = *DAT_803dd708;
              uVar18 = (**(code **)(iVar12 + 8))(uVar8,0x198,0,4);
              iVar14 = iVar14 + 1;
            } while (iVar14 < 4);
            *(float *)(iVar13 + 0x40) = (float)(dVar15 * dVar17 + (double)*(float *)(uVar6 + 0xc));
            *(float *)(iVar13 + 0x48) = (float)(dVar16 * dVar17 + (double)*(float *)(uVar6 + 0x14));
            cVar4 = *(char *)(iVar13 + 0x4e);
            if ((cVar4 == '\0') || (cVar4 == '\x01')) {
              FUN_800379bc(uVar18,dVar19,dVar21,in_f4,in_f5,in_f6,in_f7,in_f8,uVar6,0x60003,
                           iVar13 + 0x34,0,uVar10,uVar11,iVar12,in_r10);
            }
            else if (((byte)(cVar4 - 2U) < 2) || (cVar4 == '\x1e')) {
              FUN_800379bc(uVar18,dVar19,dVar21,in_f4,in_f5,in_f6,in_f7,in_f8,uVar6,0x60004,
                           iVar13 + 0x34,0,uVar10,uVar11,iVar12,in_r10);
            }
            *(undefined *)(iVar13 + 0x27) = 2;
          }
        }
      }
    }
  }
  if (*(char *)(iVar13 + 0x24) == '\0') {
    if ((*(char *)(iVar13 + 0x4e) == '\x1e') && (*(short *)(iVar13 + 0x32) != -1)) {
      (**(code **)(*DAT_803dd6fc + 0x20))(iVar13 + 0x32);
    }
    if (*(char *)(iVar13 + 0x4c) == '\x01') {
      (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
      *(undefined *)(iVar13 + 0x4c) = 0;
    }
  }
  fVar2 = FLOAT_803e69a8;
  *(float *)(iVar13 + 4) = FLOAT_803e69a8;
  *(float *)(iVar13 + 0xc) = fVar2;
  *(float *)(iVar13 + 0x14) = fVar2;
  *(undefined4 *)(iVar13 + 8) = *(undefined4 *)(iVar13 + 4);
  *(undefined4 *)(iVar13 + 0x10) = *(undefined4 *)(iVar13 + 0xc);
  *(float *)(iVar13 + 0x18) = (float)((double)*(float *)(iVar13 + 0x14) + dVar22);
  *(undefined *)(iVar13 + 0x26) = 8;
  *(float *)(param_1 + 0x98) = FLOAT_803e69e0 * FLOAT_803dc074 + *(float *)(param_1 + 0x98);
  if (FLOAT_803e69b0 < *(float *)(param_1 + 0x98)) {
    *(float *)(param_1 + 0x98) = *(float *)(param_1 + 0x98) - FLOAT_803e69b0;
  }
  return;
}

