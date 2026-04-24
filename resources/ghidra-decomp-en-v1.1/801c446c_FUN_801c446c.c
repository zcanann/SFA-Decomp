// Function: FUN_801c446c
// Entry: 801c446c
// Size: 1768 bytes

/* WARNING: Removing unreachable block (ram,0x801c4b2c) */
/* WARNING: Removing unreachable block (ram,0x801c4b24) */
/* WARNING: Removing unreachable block (ram,0x801c4b1c) */
/* WARNING: Removing unreachable block (ram,0x801c4b14) */
/* WARNING: Removing unreachable block (ram,0x801c4b0c) */
/* WARNING: Removing unreachable block (ram,0x801c4b04) */
/* WARNING: Removing unreachable block (ram,0x801c44a4) */
/* WARNING: Removing unreachable block (ram,0x801c449c) */
/* WARNING: Removing unreachable block (ram,0x801c4494) */
/* WARNING: Removing unreachable block (ram,0x801c448c) */
/* WARNING: Removing unreachable block (ram,0x801c4484) */
/* WARNING: Removing unreachable block (ram,0x801c447c) */

void FUN_801c446c(uint param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 uVar13;
  double dVar14;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  undefined8 local_88;
  undefined8 local_78;
  
  iVar9 = *(int *)(param_1 + 0x4c);
  iVar8 = *(int *)(param_1 + 0xb8);
  *(ushort *)(iVar8 + 0x2c) = *(short *)(iVar8 + 0x2c) - (ushort)DAT_803dc070;
  uVar2 = FUN_80020078((int)*(short *)(iVar9 + 0x1e));
  if (uVar2 == 0) {
    if (*(short *)(iVar8 + 0x2c) < 0) {
      if (*(char *)(iVar8 + 0x25) == '\0') {
        *(undefined2 *)(iVar8 + 0x2c) = 400;
        FUN_8000bb38(param_1,0x78);
        *(float *)(iVar8 + 0x1c) = FLOAT_803e5b58;
      }
      else {
        *(undefined2 *)(iVar8 + 0x2c) = 0x113;
      }
      *(undefined *)(iVar8 + 0x49) = 0;
    }
    else if (*(short *)(iVar8 + 0x2c) < *(short *)(iVar8 + 0x2e)) {
      if (*(char *)(iVar8 + 0x49) == '\0') {
        FUN_8000bb38(param_1,0x79);
        if (*(char *)(iVar8 + 0x25) == '\0') {
          FUN_8000bb38(param_1,0x77);
        }
        *(undefined *)(iVar8 + 0x49) = 1;
        if (DAT_803de838 != (int *)0x0) {
          (**(code **)(*DAT_803de838 + 4))(param_1,10,0,0x10004,0xffffffff,0);
        }
      }
      if (*(short *)(iVar8 + 0x2c) < 0x28) {
        FUN_8000b7dc(param_1,0x40);
        if ((FLOAT_803e5b58 <= *(float *)(iVar8 + 0x1c)) && (*(char *)(iVar8 + 0x25) == '\0')) {
          *(float *)(iVar8 + 0x1c) = -(FLOAT_803e5b5c * FLOAT_803dc074 - *(float *)(iVar8 + 0x1c));
        }
      }
      else if (*(short *)(iVar8 + 0x2c) < 0x8c) {
        if ((*(char *)(iVar8 + 0x49) == '\x01') &&
           (*(undefined *)(iVar8 + 0x49) = 2, DAT_803de838 != (int *)0x0)) {
          (**(code **)(*DAT_803de838 + 4))(param_1,0xb,0,0x10004,0xffffffff,0);
        }
      }
      else if (*(float *)(iVar8 + 0x1c) <= FLOAT_803e5b60) {
        *(float *)(iVar8 + 0x1c) = FLOAT_803e5b64 * FLOAT_803dc074 + *(float *)(iVar8 + 0x1c);
      }
    }
  }
  if (*(char *)(iVar8 + 0x24) != '\0') {
    FUN_8000b8a8((double)FLOAT_803e5b6c,param_1,0x40,
                 (byte)(int)(FLOAT_803e5b68 * *(float *)(iVar8 + 0x1c)));
  }
  local_88 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0x1a) ^ 0x80000000);
  dVar19 = (double)(float)(local_88 - DOUBLE_803e5b98);
  dVar17 = (double)(float)(dVar19 * dVar19);
  dVar10 = (double)FUN_80294964();
  dVar11 = (double)FUN_802945e0();
  dVar15 = -(double)(float)((double)*(float *)(param_1 + 0xc) * dVar10 +
                           (double)(float)((double)*(float *)(param_1 + 0x14) * dVar11));
  iVar3 = FUN_8002bac4();
  *(byte *)(iVar8 + 0x27) = *(char *)(iVar8 + 0x27) - DAT_803dc070;
  if (*(char *)(iVar8 + 0x27) < '\0') {
    *(undefined *)(iVar8 + 0x27) = 0;
  }
  if ((*(char *)(iVar8 + 0x4a) == '\x01') ||
     ((FLOAT_803e5b58 <
       (float)(dVar15 + (double)(float)(dVar10 * (double)*(float *)(iVar3 + 0xc) +
                                       (double)(float)(dVar11 * (double)*(float *)(iVar3 + 0x14))))
      && (*(char *)(iVar8 + 0x4a) != '\0')))) {
    *(ushort *)(iVar8 + 0x2a) = *(short *)(iVar8 + 0x2a) - (ushort)DAT_803dc070;
    if (*(short *)(iVar8 + 0x2a) < 0) {
      *(undefined2 *)(iVar8 + 0x2a) = 0;
      *(undefined *)(iVar8 + 0x25) = 0;
    }
  }
  else {
    *(ushort *)(iVar8 + 0x2a) = *(short *)(iVar8 + 0x2a) + (ushort)DAT_803dc070;
    if (0x3c < *(short *)(iVar8 + 0x2a)) {
      *(undefined2 *)(iVar8 + 0x2a) = 0x3c;
      *(undefined *)(iVar8 + 0x25) = 1;
    }
  }
  if (*(char *)(iVar8 + 0x25) == '\0') {
    *(byte *)(iVar8 + 0x24) = *(byte *)(iVar8 + 0x49) & 3;
  }
  else {
    *(undefined *)(iVar8 + 0x24) = 1;
  }
  uVar2 = FUN_80020078((int)*(short *)(iVar9 + 0x1e));
  if (uVar2 != 0) {
    *(undefined *)(iVar8 + 0x24) = 0;
  }
  if (*(char *)(iVar8 + 0x27) == '\0') {
    *(undefined2 *)(iVar8 + 0x28) = 0;
  }
  if (((iVar3 != 0) && (*(char *)(iVar8 + 0x27) == '\0')) && (*(char *)(iVar8 + 0x24) != '\0')) {
    local_78 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x26) ^ 0x80000000);
    dVar16 = (double)(FLOAT_803e5b78 + (float)(local_78 - DOUBLE_803e5b98));
    dVar12 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10));
    if ((dVar12 < dVar16) && (-(double)(float)((double)FLOAT_803e5b7c + dVar16) < dVar12)) {
      dVar12 = (double)*(float *)(iVar3 + 0xc);
      dVar14 = (double)(float)(dVar12 - (double)*(float *)(param_1 + 0xc));
      fVar1 = (float)((double)*(float *)(iVar3 + 0x14) - (double)*(float *)(param_1 + 0x14));
      if ((double)(float)(dVar14 * dVar14 + (double)(fVar1 * fVar1)) < dVar17) {
        dVar18 = (double)(float)(dVar15 + (double)(float)(dVar10 * dVar12 +
                                                         (double)(float)(dVar11 * (double)*(float *)
                                                  (iVar3 + 0x14))));
        dVar17 = dVar18;
        if (dVar18 < (double)FLOAT_803e5b58) {
          dVar17 = -dVar18;
        }
        if ((double)FLOAT_803e5b80 < dVar17) {
          dVar17 = (double)FLOAT_803e5b80;
        }
        *(short *)(iVar8 + 0x28) =
             (short)(int)(FLOAT_803e5b84 * (float)((double)FLOAT_803e5b80 - dVar17));
        if (*(char *)(iVar8 + 0x48) == '\x01') {
          (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
          *(undefined *)(iVar8 + 0x48) = 0;
        }
        if ((dVar18 < dVar16) && (-dVar16 < dVar18)) {
          fVar1 = FLOAT_803e5b8c;
          if ((float)(dVar15 + (double)(float)(dVar10 * (double)*(float *)(iVar3 + 0x80) +
                                              (double)(float)(dVar11 * (double)*(float *)(iVar3 + 
                                                  0x88)))) < FLOAT_803e5b58) {
            fVar1 = FLOAT_803e5b88;
          }
          dVar15 = (double)fVar1;
          iVar9 = FUN_80297300(iVar3);
          if (iVar9 == 0x1d7) {
            FUN_800201ac(0x468,1);
          }
          else {
            FUN_8000bb38(param_1,0x7a);
            iVar9 = 0;
            do {
              uVar4 = FUN_8002bac4();
              uVar5 = 0xffffffff;
              uVar6 = 0;
              iVar7 = *DAT_803dd708;
              uVar13 = (**(code **)(iVar7 + 8))(uVar4,0x28b,0,4);
              iVar9 = iVar9 + 1;
            } while (iVar9 < 4);
            *(float *)(iVar8 + 0x3c) = (float)(dVar10 * dVar15 + (double)*(float *)(iVar3 + 0xc));
            *(float *)(iVar8 + 0x44) = (float)(dVar11 * dVar15 + (double)*(float *)(iVar3 + 0x14));
            if ((*(char *)(iVar8 + 0x4a) == '\0') || (*(char *)(iVar8 + 0x4a) == '\x01')) {
              FUN_800379bc(uVar13,dVar12,dVar14,in_f4,in_f5,in_f6,in_f7,in_f8,iVar3,0x60003,
                           iVar8 + 0x30,0,uVar5,uVar6,iVar7,in_r10);
            }
            *(undefined *)(iVar8 + 0x27) = 0x14;
          }
        }
      }
    }
  }
  if ((*(char *)(iVar8 + 0x24) == '\0') && (*(char *)(iVar8 + 0x48) == '\x01')) {
    (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
    *(undefined *)(iVar8 + 0x48) = 0;
  }
  fVar1 = FLOAT_803e5b58;
  *(float *)(iVar8 + 4) = FLOAT_803e5b58;
  *(float *)(iVar8 + 0xc) = fVar1;
  *(float *)(iVar8 + 0x14) = fVar1;
  *(undefined4 *)(iVar8 + 8) = *(undefined4 *)(iVar8 + 4);
  *(undefined4 *)(iVar8 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
  *(float *)(iVar8 + 0x18) = (float)((double)*(float *)(iVar8 + 0x14) + dVar19);
  *(undefined *)(iVar8 + 0x26) = 8;
  *(float *)(param_1 + 0x98) = FLOAT_803e5b90 * FLOAT_803dc074 + *(float *)(param_1 + 0x98);
  if (FLOAT_803e5b60 < *(float *)(param_1 + 0x98)) {
    *(float *)(param_1 + 0x98) = *(float *)(param_1 + 0x98) - FLOAT_803e5b60;
  }
  return;
}

