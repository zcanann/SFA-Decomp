// Function: FUN_8029c514
// Entry: 8029c514
// Size: 2836 bytes

/* WARNING: Removing unreachable block (ram,0x8029d008) */
/* WARNING: Removing unreachable block (ram,0x8029d000) */
/* WARNING: Removing unreachable block (ram,0x8029c52c) */
/* WARNING: Removing unreachable block (ram,0x8029c524) */

void FUN_8029c514(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,float *param_12,
                 undefined4 *param_13,undefined4 param_14,int param_15,int param_16)

{
  float fVar1;
  char cVar2;
  short sVar3;
  bool bVar4;
  ushort uVar6;
  undefined2 uVar7;
  undefined4 uVar5;
  short *psVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  undefined8 extraout_f1;
  double in_f31;
  undefined8 uVar17;
  undefined8 local_50;
  undefined8 local_48;
  
  uVar17 = FUN_80286840();
  psVar8 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar13 = (int)uVar17;
  iVar15 = *(int *)(psVar8 + 0x5c);
  uVar17 = extraout_f1;
  iVar9 = FUN_8029c15c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar8,
                       iVar13,param_11,param_12,param_13,param_14,param_15,param_16);
  iVar11 = DAT_803df0cc;
  if (iVar9 == 0) {
    *(undefined *)(iVar13 + 0x34d) = 1;
    DAT_803dd2d4 = 5;
    if (*(char *)(iVar13 + 0x27a) == '\0') {
      if (DAT_803df0d9 != '\0') {
        FUN_80014acc((double)FLOAT_803e8b70);
        *(undefined4 *)(iVar13 + 0x308) = 0;
        goto LAB_8029d000;
      }
      bVar4 = false;
      if (FLOAT_803e8b3c < *(float *)(iVar13 + 0x2a0)) {
        if ((*(uint *)(iVar13 + 0x314) & 0x200) != 0) {
          FUN_80014acc((double)FLOAT_803e8ba8);
          FUN_8000bb38((uint)psVar8,0x3cd);
          *(ushort *)(iVar15 + 0x8d8) = *(ushort *)(iVar15 + 0x8d8) | 4;
        }
        if ((*(uint *)(iVar13 + 0x314) & 0x400) != 0) {
          FUN_80014acc((double)FLOAT_803e8ba8);
          FUN_8000bb38((uint)psVar8,0x3cd);
          *(ushort *)(iVar15 + 0x8d8) = *(ushort *)(iVar15 + 0x8d8) | 4;
        }
        if (((*(byte *)(iVar13 + 0x356) & 1) == 0) &&
           (*(float *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x50) <
            *(float *)(psVar8 + 0x4c))) {
          if (*(short *)(iVar15 + 0x81a) == 0) {
            uVar6 = 0x2de;
          }
          else {
            uVar6 = 0x1c;
          }
          FUN_8000bb38((uint)psVar8,uVar6);
          *(byte *)(iVar13 + 0x356) = *(byte *)(iVar13 + 0x356) | 1;
        }
        if (((*(byte *)(iVar13 + 0x356) & 2) == 0) &&
           (*(float *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x54) <
            *(float *)(psVar8 + 0x4c))) {
          FUN_8000bb38((uint)psVar8,0x1a);
          *(byte *)(iVar13 + 0x356) = *(byte *)(iVar13 + 0x356) | 2;
        }
      }
      iVar9 = *(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0;
      if (-1 < *(char *)(iVar9 + 0x15)) {
        if ((*(float *)(iVar9 + 0x28) < *(float *)(psVar8 + 0x4c)) &&
           (*(byte *)(iVar13 + 0x34a) = *(byte *)(iVar13 + 0x34a) | 2,
           *(char *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x6c) !=
           '\0')) {
          *(byte *)(iVar13 + 0x34a) = *(byte *)(iVar13 + 0x34a) | 4;
          *(undefined *)(iVar15 + 0x8c0) = 0;
        }
        if (*(float *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x20) <
            *(float *)(psVar8 + 0x4c)) {
          *(byte *)(iVar13 + 0x34a) = *(byte *)(iVar13 + 0x34a) | 1;
        }
        if (*(float *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x24) <
            *(float *)(psVar8 + 0x4c)) {
          *(byte *)(iVar13 + 0x34a) = *(byte *)(iVar13 + 0x34a) & 0xfe;
        }
        if (((*(uint *)(iVar13 + 0x31c) & 0x100) != 0) && ((*(byte *)(iVar13 + 0x34a) & 1) != 0)) {
          *(byte *)(iVar13 + 0x34a) = *(byte *)(iVar13 + 0x34a) | 4;
          *(uint *)(iVar13 + 0x31c) = *(uint *)(iVar13 + 0x31c) & 0xfffffeff;
          FUN_80014b68(0,0x100);
          *(undefined *)(iVar15 + 0x8c0) = *(undefined *)(iVar13 + 0x34b);
        }
        if (((*(byte *)(iVar13 + 0x34a) & 4) != 0) && ((*(byte *)(iVar13 + 0x34a) & 2) != 0)) {
          uVar10 = FUN_8014c950(*(int *)(iVar13 + 0x2d0));
          iVar9 = *(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0;
          if ((float)((double)CONCAT44(0x43300000,uVar10 & 0xff) - DOUBLE_803e8bd0) <
              *(float *)(iVar9 + 0x8c)) {
            *(undefined *)(iVar15 + 0x8a9) = *(undefined *)(iVar9 + 0x90);
          }
          else {
            *(undefined *)(iVar15 + 0x8a9) =
                 *(undefined *)(iVar9 + (uint)*(byte *)(iVar15 + 0x8c0) + 0x15);
          }
          bVar4 = true;
        }
      }
    }
    else {
      DAT_803df0d9 = '\0';
      bVar4 = true;
      *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) & 0xffffffbf;
      *(undefined *)(*(int *)(psVar8 + 0x2a) + 0x70) = 0;
      fVar1 = FLOAT_803e8b3c;
      *(float *)(iVar15 + 0x828) = FLOAT_803e8b3c;
      *(undefined *)(iVar15 + 0x8ab) = 0;
      *(undefined4 *)(iVar15 + 0x4c0) = 0;
      *(undefined *)(iVar15 + 0x8cd) = 0xff;
      *(float *)(iVar13 + 0x294) = fVar1;
      *(float *)(iVar13 + 0x284) = fVar1;
      *(float *)(iVar13 + 0x280) = fVar1;
      *(float *)(psVar8 + 0x12) = fVar1;
      *(float *)(psVar8 + 0x14) = fVar1;
      *(float *)(psVar8 + 0x16) = fVar1;
    }
    if (*(int *)(iVar13 + 0x2d0) == 0) {
      if (((*(char *)(iVar13 + 0x27a) == '\0') || (*(int *)(iVar15 + 0x4b8) == 0)) ||
         (*(short *)(iVar15 + 0x4b4) != 1)) {
        if (*(char *)(iVar13 + 0x27a) != '\0') {
          uVar7 = (undefined2)*(undefined4 *)(iVar15 + 0x474);
          *(undefined2 *)(iVar15 + 0x478) = uVar7;
          *(undefined2 *)(iVar15 + 0x484) = uVar7;
        }
      }
      else {
        if (*(int *)(iVar15 + 0x4a8) < 0x4000) {
          local_50 = (double)CONCAT44(0x43300000,*(uint *)(iVar15 + 0x4a4) ^ 0x80000000);
          in_f31 = (double)(float)(local_50 - DOUBLE_803e8b58);
        }
        *(short *)(iVar15 + 0x478) =
             (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar15 + 0x478) ^
                                                           0x80000000) - DOUBLE_803e8b58) + in_f31);
        *(undefined2 *)(iVar15 + 0x484) = *(undefined2 *)(iVar15 + 0x478);
      }
    }
    else {
      if ((*(byte *)(iVar15 + 0x8a9) < 5) || (9 < *(byte *)(iVar15 + 0x8a9))) {
        fVar1 = (float)((double)CONCAT44(0x43300000,*(uint *)(iVar15 + 0x4a4) ^ 0x80000000) -
                       DOUBLE_803e8b58) / FLOAT_803e8c50;
      }
      else {
        fVar1 = (float)((double)CONCAT44(0x43300000,*(uint *)(iVar15 + 0x4a4) ^ 0x80000000) -
                       DOUBLE_803e8b58);
      }
      *(short *)(iVar15 + 0x478) =
           (short)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar15 + 0x478) ^ 0x80000000) -
                               DOUBLE_803e8b58) + fVar1);
      *(undefined2 *)(iVar15 + 0x484) = *(undefined2 *)(iVar15 + 0x478);
    }
    if (bVar4) {
      *(uint *)(psVar8 + 0x2e) =
           *(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x60;
      iVar9 = *(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0;
      if ((int)psVar8[0x50] != (int)*(short *)(&DAT_8033431c + *(short *)(iVar9 + 2) * 2)) {
        FUN_8003042c((double)*(float *)(iVar9 + 0x68),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,psVar8,
                     (int)*(short *)(&DAT_8033431c + *(short *)(iVar9 + 2) * 2),0,(int)psVar8[0x50],
                     param_13,param_14,param_15,param_16);
        FUN_8002f66c((int)psVar8,2);
      }
      *(byte *)(iVar13 + 0x34a) = *(byte *)(iVar13 + 0x34a) & 0x10;
      *(undefined4 *)(iVar13 + 0x2a0) =
           *(undefined4 *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x1c)
      ;
      *(undefined4 *)(iVar15 + 0x824) = *(undefined4 *)(iVar13 + 0x2a0);
      *(undefined *)(iVar15 + 0x8cf) = 0;
      *(float *)(iVar13 + 0x284) = FLOAT_803e8b3c;
      *(undefined *)(iVar13 + 0x356) = 0;
      if (*(int *)(iVar13 + 0x2d0) != 0) {
        if ((*(byte *)(iVar15 + 0x8a9) < 5) || (9 < *(byte *)(iVar15 + 0x8a9))) {
          (**(code **)(*DAT_803dd70c + 0x30))(uVar17,psVar8,iVar13,2);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x30))(uVar17,psVar8,iVar13,1);
        }
        sVar3 = *psVar8;
        *(short *)(iVar15 + 0x484) = sVar3;
        *(short *)(iVar15 + 0x478) = sVar3;
      }
      if (*(int *)(psVar8 + 0x2a) != 0) {
        *(undefined *)(*(int *)(psVar8 + 0x2a) + 0x70) = 0;
      }
      *(undefined *)(iVar15 + 0x8cd) = 0xff;
      if (*(short *)(iVar11 + 0x44) == 0x2d) {
        FUN_8016ecc8(iVar11);
        (**(code **)(**(int **)(iVar11 + 0x68) + 0x38))
                  (iVar11,*(undefined *)
                           (*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x5c
                           ));
        iVar9 = *(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0;
        (**(code **)(**(int **)(iVar11 + 0x68) + 0x4c))
                  ((double)*(float *)(iVar9 + 0x48),(double)*(float *)(iVar9 + 0x4c),iVar11);
      }
      fVar1 = FLOAT_803e8b3c;
      *(float *)(iVar15 + 0x7d8) = FLOAT_803e8b3c;
      *(float *)(iVar15 + 0x828) = fVar1;
      *(undefined *)(iVar15 + 0x8ab) = 0;
      *(undefined4 *)(iVar15 + 0x4c0) = 0;
    }
    *(undefined *)(*(int *)(psVar8 + 0x2a) + 0x6e) = 0xb;
    *(undefined *)(*(int *)(psVar8 + 0x2a) + 0x6f) =
         *(undefined *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x14);
    iVar11 = *(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0;
    fVar1 = *(float *)(iVar11 + 0xa0);
    if (FLOAT_803e8b3c <= fVar1) {
      if ((*(float *)(psVar8 + 0x4c) <= fVar1) ||
         (*(float *)(iVar11 + 0xa4) <= *(float *)(psVar8 + 0x4c))) {
        *(float *)(iVar15 + 0x7d8) = FLOAT_803e8b3c;
      }
      else {
        if (FLOAT_803e8b3c == *(float *)(iVar15 + 0x7d8)) {
          FUN_8000bb38((uint)psVar8,0x21b);
        }
        *(float *)(iVar15 + 0x7d8) = FLOAT_803e8b6c * FLOAT_803dc074 + *(float *)(iVar15 + 0x7d8);
        if (FLOAT_803e8c54 < *(float *)(iVar15 + 0x7d8)) {
          *(float *)(iVar15 + 0x7d8) = FLOAT_803e8c54;
        }
      }
    }
    if (((*(byte *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x88) & 2)
         != 0) && (*(int *)(iVar15 + 0x4c0) != 0)) {
      if (*(byte *)(iVar15 + 0x8ab) < *(byte *)(iVar15 + 0x8ac)) {
        fVar1 = *(float *)(iVar15 + 0x828) - FLOAT_803e8b78;
        *(float *)(iVar15 + 0x828) = fVar1;
        if (fVar1 <= FLOAT_803e8b3c) {
          FUN_80036548(*(int *)(iVar15 + 0x4c0),(int)psVar8,'\v',1,0);
          *(char *)(iVar15 + 0x8ab) = *(char *)(iVar15 + 0x8ab) + '\x01';
          local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar15 + 0x8ad));
          *(float *)(iVar15 + 0x828) = (float)(local_48 - DOUBLE_803e8bd0);
        }
      }
      else {
        *(undefined4 *)(iVar15 + 0x4c0) = 0;
      }
    }
    iVar11 = 0;
    *(undefined4 *)(*(int *)(psVar8 + 0x2a) + 0x48) = 0;
    iVar9 = 0;
    iVar16 = 3;
    do {
      iVar14 = (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0;
      iVar12 = *(int *)(iVar15 + 0x3dc) + iVar14 + iVar11;
      if ((*(float *)(iVar12 + 0x30) <= *(float *)(psVar8 + 0x4c)) &&
         (*(float *)(psVar8 + 0x4c) <= *(float *)(iVar12 + 0x3c))) {
        if (*(char *)(*(int *)(psVar8 + 0x2a) + 0x70) == '\0') {
          cVar2 = *(char *)(*(int *)(iVar15 + 0x3dc) + iVar14 + iVar9 + 0x5d);
          if (cVar2 == '\x02') {
            uVar5 = 0x100000;
          }
          else if (cVar2 < '\x02') {
            if (cVar2 == '\0') {
              uVar5 = 0xc;
            }
            else if (cVar2 < '\0') {
              if (cVar2 < -1) goto LAB_8029ce28;
              uVar5 = 0;
            }
            else {
              uVar5 = 3;
            }
          }
          else if (cVar2 == '\x04') {
            uVar5 = 0xf;
          }
          else if (cVar2 < '\x04') {
            uVar5 = 0x10000;
          }
          else {
LAB_8029ce28:
            uVar5 = 0;
          }
          *(undefined4 *)(*(int *)(psVar8 + 0x2a) + 0x48) = uVar5;
        }
        if (iVar9 != *(char *)(iVar15 + 0x8cd)) {
          *(undefined *)(*(int *)(psVar8 + 0x2a) + 0x70) = 0;
          *(char *)(iVar15 + 0x8cd) = (char)iVar9;
          *(undefined *)(iVar15 + 0x8ab) = 0;
          *(float *)(iVar15 + 0x828) = FLOAT_803e8b3c;
          *(undefined4 *)(iVar15 + 0x4c0) = 0;
        }
        break;
      }
      iVar11 = iVar11 + 4;
      iVar9 = iVar9 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    (**(code **)(*DAT_803dd70c + 0x20))(uVar17,psVar8,iVar13,3);
    if (*(char *)(iVar13 + 0x346) == '\0') {
      if (*(float *)(*(int *)(iVar15 + 0x3dc) + (uint)*(byte *)(iVar15 + 0x8a9) * 0xb0 + 0x2c) <=
          *(float *)(psVar8 + 0x4c)) {
        if (*(int *)(iVar13 + 0x2d0) == 0) {
          if (((*(uint *)(iVar13 + 0x31c) & 0x100) != 0) &&
             (FLOAT_803e8b44 < *(float *)(iVar13 + 0x298))) {
            *(short *)(iVar15 + 0x478) =
                 *(short *)(iVar15 + 0x478) + (short)*(undefined4 *)(iVar15 + 0x480) * 0xb6;
            *(undefined2 *)(iVar15 + 0x484) = *(undefined2 *)(iVar15 + 0x478);
            *(undefined4 *)(iVar15 + 0x47c) = 0;
            *(undefined4 *)(iVar15 + 0x480) = 0;
            *(undefined4 *)(iVar15 + 0x488) = 0;
            *(undefined4 *)(iVar15 + 0x48c) = 0;
            *(undefined4 *)(iVar13 + 0x308) = 0;
          }
        }
        else if ((*(uint *)(iVar13 + 0x31c) & 0x100) != 0) {
          *(undefined *)(*(int *)(psVar8 + 0x2a) + 0x70) = 0;
          *(undefined *)(iVar15 + 0x8cd) = 0xff;
          (**(code **)(*DAT_803dd70c + 0x30))(uVar17,psVar8,iVar13,2);
          sVar3 = *psVar8;
          *(short *)(iVar15 + 0x484) = sVar3;
          *(short *)(iVar15 + 0x478) = sVar3;
          *(undefined4 *)(iVar13 + 0x308) = 0;
        }
      }
    }
    else {
      *(undefined *)(*(int *)(psVar8 + 0x2a) + 0x70) = 0;
      if (*(int *)(iVar13 + 0x2d0) == 0) {
        *(byte *)(iVar15 + 0x3f1) = *(byte *)(iVar15 + 0x3f1) & 0x7f | 0x80;
        *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) | 0x800000;
        *(code **)(iVar13 + 0x308) = FUN_802a58ac;
      }
      else {
        *(code **)(iVar13 + 0x308) = FUN_8029d028;
      }
    }
  }
LAB_8029d000:
  FUN_8028688c();
  return;
}

