// Function: FUN_80196f0c
// Entry: 80196f0c
// Size: 1752 bytes

/* WARNING: Removing unreachable block (ram,0x801975bc) */
/* WARNING: Removing unreachable block (ram,0x801975b4) */
/* WARNING: Removing unreachable block (ram,0x801975ac) */
/* WARNING: Removing unreachable block (ram,0x801975a4) */
/* WARNING: Removing unreachable block (ram,0x8019759c) */
/* WARNING: Removing unreachable block (ram,0x80196f3c) */
/* WARNING: Removing unreachable block (ram,0x80196f34) */
/* WARNING: Removing unreachable block (ram,0x80196f2c) */
/* WARNING: Removing unreachable block (ram,0x80196f24) */
/* WARNING: Removing unreachable block (ram,0x80196f1c) */

void FUN_80196f0c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  short sVar5;
  int iVar4;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined auStack_a8 [12];
  float local_9c;
  float local_98;
  float local_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined8 local_88;
  undefined8 local_80;
  longlong local_78;
  undefined4 local_70;
  uint uStack_6c;
  undefined8 local_68;
  
  iVar9 = *(int *)(param_9 + 0x5c);
  bVar1 = *(byte *)(iVar9 + 0x29e);
  if ((bVar1 & 2) == 0) {
    iVar8 = *(int *)(param_9 + 0x26);
    if ((bVar1 & 1) == 0) {
      if (*(char *)((int)param_9 + 0xad) == '\0') {
        uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x40));
        if ((uVar6 != 0) || (*(short *)(iVar8 + 0x40) == -1)) {
          *(byte *)(iVar9 + 0x29e) = *(byte *)(iVar9 + 0x29e) | 1;
          FUN_800201ac((int)*(short *)(iVar8 + 0x3e),1);
          DAT_803de780 = '\x01';
        }
      }
      else if (DAT_803de780 != '\0') {
        *(byte *)(iVar9 + 0x29e) = bVar1 | 1;
      }
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    else {
      *(undefined *)(param_9 + 0x1b) = 0xff;
      sVar5 = *(short *)(iVar9 + 0x29c) + (ushort)DAT_803dc070;
      *(short *)(iVar9 + 0x29c) = sVar5;
      if ((int)(uint)*(ushort *)(iVar8 + 0x38) <= (int)sVar5) {
        *(byte *)(iVar9 + 0x29e) = *(byte *)(iVar9 + 0x29e) | 2;
      }
      uVar6 = (uint)*(ushort *)(iVar8 + 0x3a);
      if (((int)uVar6 < (int)*(short *)(iVar9 + 0x29c)) &&
         (uVar7 = *(ushort *)(iVar8 + 0x38) - uVar6, uVar7 != 0)) {
        local_88 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        iVar4 = (int)(FLOAT_803e4ce4 *
                     (FLOAT_803e4ce0 -
                     (float)((double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar9 + 0x29c) - uVar6 ^ 0x80000000) -
                            DOUBLE_803e4cd8) / (float)(local_88 - DOUBLE_803e4cd8)));
        if (iVar4 < 0x100) {
          if (iVar4 < 0) {
            iVar4 = 0;
          }
        }
        else {
          iVar4 = 0xff;
        }
        *(char *)(param_9 + 0x1b) = (char)iVar4;
      }
      *(float *)(param_9 + 0x12) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x290) + *(float *)(param_9 + 0x12);
      *(float *)(param_9 + 0x14) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x294) + *(float *)(param_9 + 0x14);
      *(float *)(param_9 + 0x16) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x298) + *(float *)(param_9 + 0x16);
      *(float *)(iVar9 + 0x278) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x284) + *(float *)(iVar9 + 0x278);
      *(float *)(iVar9 + 0x27c) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x288) + *(float *)(iVar9 + 0x27c);
      *(float *)(iVar9 + 0x280) =
           FLOAT_803dc074 * *(float *)(iVar9 + 0x28c) + *(float *)(iVar9 + 0x280);
      if ((*(byte *)(iVar9 + 0x29f) & 1) == 0) {
        if (FLOAT_803e4ccc < *(float *)(param_9 + 0x12)) {
          *(float *)(param_9 + 0x12) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(param_9 + 0x12) < FLOAT_803e4ccc) {
        *(float *)(param_9 + 0x12) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 2) == 0) {
        if (FLOAT_803e4ccc < *(float *)(param_9 + 0x16)) {
          *(float *)(param_9 + 0x16) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(param_9 + 0x16) < FLOAT_803e4ccc) {
        *(float *)(param_9 + 0x16) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 4) == 0) {
        if (FLOAT_803e4ccc < *(float *)(iVar9 + 0x278)) {
          *(float *)(iVar9 + 0x278) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(iVar9 + 0x278) < FLOAT_803e4ccc) {
        *(float *)(iVar9 + 0x278) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 8) == 0) {
        if (FLOAT_803e4ccc < *(float *)(iVar9 + 0x27c)) {
          *(float *)(iVar9 + 0x27c) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(iVar9 + 0x27c) < FLOAT_803e4ccc) {
        *(float *)(iVar9 + 0x27c) = FLOAT_803e4ccc;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 0x10) == 0) {
        if (FLOAT_803e4ccc < *(float *)(iVar9 + 0x280)) {
          *(float *)(iVar9 + 0x280) = FLOAT_803e4ccc;
        }
      }
      else if (*(float *)(iVar9 + 0x280) < FLOAT_803e4ccc) {
        *(float *)(iVar9 + 0x280) = FLOAT_803e4ccc;
      }
      *(float *)(param_9 + 6) =
           *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(param_9 + 6);
      *(float *)(param_9 + 8) =
           *(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8);
      *(float *)(param_9 + 10) =
           *(float *)(param_9 + 0x16) * FLOAT_803dc074 + *(float *)(param_9 + 10);
      dVar11 = DOUBLE_803e4cd8;
      local_80 = (double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000);
      iVar4 = (int)(*(float *)(iVar9 + 0x278) * FLOAT_803dc074 + (float)(local_80 - DOUBLE_803e4cd8)
                   );
      local_88 = (double)(longlong)iVar4;
      *param_9 = (short)iVar4;
      uStack_8c = (int)param_9[1] ^ 0x80000000;
      local_90 = 0x43300000;
      iVar4 = (int)(*(float *)(iVar9 + 0x27c) * FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,uStack_8c) - dVar11));
      local_78 = (longlong)iVar4;
      param_9[1] = (short)iVar4;
      uStack_6c = (int)param_9[2] ^ 0x80000000;
      local_70 = 0x43300000;
      iVar4 = (int)(*(float *)(iVar9 + 0x280) * FLOAT_803dc074 +
                   (float)((double)CONCAT44(0x43300000,uStack_6c) - dVar11));
      local_68 = (double)(longlong)iVar4;
      param_9[2] = (short)iVar4;
      if ((*(byte *)(iVar8 + 0x3c) & 2) != 0) {
        (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_9,iVar9);
        (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar9);
        (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar9);
        if (*(char *)(iVar9 + 0x261) != '\0') {
          dVar14 = -(double)*(float *)(param_9 + 0x12);
          dVar13 = -(double)*(float *)(param_9 + 0x14);
          dVar15 = -(double)*(float *)(param_9 + 0x16);
          dVar11 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                               (double)(float)(dVar14 * dVar14 +
                                                              (double)(float)(dVar13 * dVar13))));
          if ((double)FLOAT_803e4ccc != dVar11) {
            dVar10 = (double)(float)((double)FLOAT_803e4ce0 / dVar11);
            dVar14 = (double)(float)(dVar14 * dVar10);
            dVar13 = (double)(float)(dVar13 * dVar10);
            dVar15 = (double)(float)(dVar15 * dVar10);
          }
          fVar2 = *(float *)(iVar9 + 0x6c);
          fVar3 = *(float *)(iVar9 + 0x70);
          dVar10 = (double)(FLOAT_803e4ce8 *
                           (float)(dVar15 * (double)fVar3 +
                                  (double)(float)(dVar14 * (double)*(float *)(iVar9 + 0x68) +
                                                 (double)(float)(dVar13 * (double)fVar2))));
          *(float *)(param_9 + 0x12) = (float)((double)*(float *)(iVar9 + 0x68) * dVar10);
          *(float *)(param_9 + 0x14) = (float)((double)fVar2 * dVar10);
          *(float *)(param_9 + 0x16) = (float)((double)fVar3 * dVar10);
          *(float *)(param_9 + 0x12) = (float)((double)*(float *)(param_9 + 0x12) - dVar14);
          *(float *)(param_9 + 0x14) = (float)((double)*(float *)(param_9 + 0x14) - dVar13);
          *(float *)(param_9 + 0x16) = (float)((double)*(float *)(param_9 + 0x16) - dVar15);
          *(float *)(param_9 + 0x14) = (float)((double)*(float *)(param_9 + 0x14) * dVar11);
          *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e4cec;
          *(float *)(param_9 + 0x12) = (float)((double)*(float *)(param_9 + 0x12) * dVar11);
          *(float *)(param_9 + 0x16) = (float)((double)*(float *)(param_9 + 0x16) * dVar11);
          fVar2 = FLOAT_803e4cf0;
          *(float *)(param_9 + 0x12) = *(float *)(param_9 + 0x12) * FLOAT_803e4cf0;
          *(float *)(param_9 + 0x16) = *(float *)(param_9 + 0x16) * fVar2;
        }
      }
      if (((*(byte *)(iVar8 + 0x3c) & 4) != 0) && (*(char *)(param_9 + 0x1b) == -1)) {
        dVar15 = (double)(*(float *)(param_9 + 6) - *(float *)(param_9 + 0x40));
        dVar14 = (double)(*(float *)(param_9 + 8) - *(float *)(param_9 + 0x42));
        dVar13 = (double)(*(float *)(param_9 + 10) - *(float *)(param_9 + 0x44));
        uVar6 = 0;
        dVar10 = (double)FLOAT_803e4cf4;
        dVar11 = DOUBLE_803e4cd8;
        do {
          local_68 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          dVar12 = (double)(float)((double)(float)(local_68 - dVar11) * dVar10);
          local_9c = (float)(dVar15 * dVar12 + (double)*(float *)(param_9 + 0x40));
          local_98 = (float)(dVar14 * dVar12 + (double)*(float *)(param_9 + 0x42));
          local_94 = (float)(dVar13 * dVar12 + (double)*(float *)(param_9 + 0x44));
          (**(code **)(*DAT_803dd708 + 8))(param_9,1000,auStack_a8,0x200001,0xffffffff,0);
          uVar6 = uVar6 + 1;
        } while ((int)uVar6 < 2);
      }
    }
  }
  else {
    if ((param_9[3] & 0x2000U) != 0) {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    *(undefined *)(param_9 + 0x1b) = 0;
  }
  return;
}

