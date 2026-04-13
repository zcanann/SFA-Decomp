// Function: FUN_80176e60
// Entry: 80176e60
// Size: 1552 bytes

/* WARNING: Removing unreachable block (ram,0x80177450) */
/* WARNING: Removing unreachable block (ram,0x80176e70) */

void FUN_80176e60(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  short sVar2;
  short *psVar3;
  ushort uVar6;
  int iVar4;
  int iVar5;
  int iVar7;
  int *piVar8;
  int extraout_r4;
  int extraout_r4_00;
  int extraout_r4_01;
  float *pfVar9;
  int in_r6;
  uint uVar10;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar17;
  float local_48;
  float local_44;
  float local_40;
  undefined8 local_38;
  undefined8 local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar17 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar7 = (int)uVar17;
  if (*(int *)(iVar7 + 0x14) == 0x30398) {
    *(undefined *)(iVar7 + 0x23) = 1;
  }
  else {
    *(undefined *)(iVar7 + 0x23) = 0xff;
  }
  *psVar3 = (ushort)*(byte *)(iVar7 + 0x22) << 8;
  *(float *)(psVar3 + 8) = FLOAT_803e4224 + *(float *)(iVar7 + 0xc);
  FUN_800372f8((int)psVar3,5);
  FUN_8002b9a0((int)psVar3,'Z');
  *(code **)(psVar3 + 0x5e) = FUN_801755b8;
  iVar12 = *(int *)(psVar3 + 0x5c);
  *(undefined *)(iVar12 + 0xb4) = 0;
  piVar8 = *(int **)(*(int *)(psVar3 + 0x3e) + *(char *)((int)psVar3 + 0xad) * 4);
  iVar11 = *piVar8;
  *(undefined4 *)(iVar12 + 0xb0) = *(undefined4 *)(iVar7 + 0x1c);
  local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar7 + 0x20));
  *(float *)(iVar12 + 0x10) = (float)(local_38 - DOUBLE_803e4268) / FLOAT_803e4264;
  *(float *)(iVar12 + 0x10) = *(float *)(iVar12 + 0x10) * *(float *)(*(int *)(psVar3 + 0x28) + 4);
  uVar6 = FUN_800284f8(*piVar8);
  local_30 = (double)CONCAT44(0x43300000,(uint)uVar6);
  dVar16 = (double)(float)(local_30 - DOUBLE_803e4268);
  *(float *)(iVar12 + 0xc) =
       (float)((double)*(float *)(iVar12 + 0x10) * dVar16 + (double)FLOAT_803e41f0);
  dVar14 = (double)FLOAT_803e41c0;
  *(float *)(iVar12 + 0x14) = FLOAT_803e41c0;
  *(undefined2 *)(iVar12 + 0xac) = *(undefined2 *)(iVar7 + 0x18);
  pfVar9 = (float *)0x0;
  FUN_8003042c(dVar14,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,psVar3,0,0,in_r6,in_r7,
               in_r8,in_r9,in_r10);
  FUN_80037a5c((int)psVar3,4);
  dVar15 = (double)FUN_80036018((int)psVar3);
  dVar14 = (double)FLOAT_803e41d8;
  iVar5 = extraout_r4;
  for (iVar13 = 0; iVar13 < (int)(uint)*(ushort *)(iVar11 + 0xe4); iVar13 = iVar13 + 1) {
    pfVar9 = &local_48;
    dVar15 = (double)FUN_80026ec4(iVar11,iVar13,pfVar9);
    if ((double)local_44 < dVar14) {
      dVar14 = (double)local_44;
    }
    iVar5 = extraout_r4_00;
  }
  for (iVar13 = 0; iVar13 < (int)(uint)*(ushort *)(iVar11 + 0xe4); iVar13 = iVar13 + 1) {
    pfVar9 = &local_48;
    dVar15 = (double)FUN_80026ec4(iVar11,iVar13,pfVar9);
    iVar5 = extraout_r4_01;
    if ((double)local_44 == dVar14) {
      in_r7 = 0;
      dVar15 = (double)local_48;
      dVar16 = (double)local_40;
      bVar1 = *(byte *)(iVar12 + 0xb4);
      pfVar9 = (float *)(uint)bVar1;
      iVar5 = (int)(char)bVar1;
      for (in_r6 = 0; in_r6 < iVar5; in_r6 = in_r6 + 1) {
        iVar4 = iVar12 + in_r6 * 0xc;
        if ((dVar15 == (double)*(float *)(iVar4 + 0x48)) &&
           (dVar16 == (double)*(float *)(iVar4 + 0x50))) {
          in_r7 = 1;
          in_r6 = iVar5;
        }
      }
      if (in_r7 == 0) {
        *(float *)(iVar12 + (char)bVar1 * 0xc + 0x48) = local_48;
        *(float *)(iVar12 + *(char *)(iVar12 + 0xb4) * 0xc + 0x4c) = local_44;
        *(float *)(iVar12 + *(char *)(iVar12 + 0xb4) * 0xc + 0x50) = local_40;
        *(char *)(iVar12 + 0xb4) = *(char *)(iVar12 + 0xb4) + '\x01';
      }
    }
  }
  if ('\x04' < *(char *)(iVar12 + 0xb4)) {
    *(undefined *)(iVar12 + 0xb4) = 4;
    FUN_80137c30(dVar15,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_PUSHPULL_OBJECT__hitpoint_overfl_803219e0,iVar5,pfVar9,in_r6,in_r7,in_r8,in_r9,
                 in_r10);
  }
  iVar11 = *(int *)(psVar3 + 0x2c);
  bVar1 = *(byte *)(iVar11 + 0x10c);
  dVar14 = (double)FLOAT_803e41c0;
  iVar5 = iVar12;
  for (iVar13 = 0; iVar13 < *(char *)(iVar12 + 0xb4); iVar13 = iVar13 + 1) {
    *(undefined4 *)(iVar5 + 0x18) = *(undefined4 *)(iVar5 + 0x48);
    *(undefined4 *)(iVar5 + 0x1c) = *(undefined4 *)(iVar5 + 0x4c);
    *(undefined4 *)(iVar5 + 0x20) = *(undefined4 *)(iVar5 + 0x50);
    dVar15 = (double)*(float *)(iVar5 + 0x18);
    if (dVar14 <= dVar15) {
      *(float *)(iVar5 + 0x18) = (float)(dVar15 - (double)FLOAT_803e4224);
    }
    else {
      *(float *)(iVar5 + 0x18) = (float)(dVar15 + (double)FLOAT_803e4224);
    }
    dVar15 = (double)*(float *)(iVar5 + 0x20);
    if (dVar14 <= dVar15) {
      *(float *)(iVar5 + 0x20) = (float)(dVar15 - (double)FLOAT_803e4224);
    }
    else {
      *(float *)(iVar5 + 0x20) = (float)(dVar15 + (double)FLOAT_803e4224);
    }
    dVar15 = (double)*(float *)(iVar5 + 0x48);
    if (dVar14 <= dVar15) {
      *(float *)(iVar5 + 0x48) = (float)(dVar15 - (double)FLOAT_803e4220);
      *(char *)(iVar12 + 0x104) = (char)iVar13;
    }
    else {
      *(float *)(iVar5 + 0x48) = (float)(dVar15 + (double)FLOAT_803e4220);
    }
    dVar15 = (double)*(float *)(iVar5 + 0x50);
    if (dVar14 <= dVar15) {
      *(float *)(iVar5 + 0x50) = (float)(dVar15 - (double)FLOAT_803e4220);
      *(char *)(iVar12 + 0x102) = (char)iVar13;
    }
    else {
      *(float *)(iVar5 + 0x50) = (float)(dVar15 + (double)FLOAT_803e4220);
    }
    FUN_80022790((double)*(float *)(iVar5 + 0x18),(double)*(float *)(iVar5 + 0x1c),
                 (double)*(float *)(iVar5 + 0x20),(float *)(iVar11 + (bVar1 + 2) * 0x40),
                 (float *)(iVar5 + 0x78),(float *)(iVar5 + 0x7c),(float *)(iVar5 + 0x80));
    iVar5 = iVar5 + 0xc;
  }
  iVar5 = iVar12;
  for (uVar10 = 0; (int)uVar10 < (int)*(char *)(iVar12 + 0xb4); uVar10 = uVar10 + 1) {
    if ((uVar10 != *(byte *)(iVar12 + 0x104)) && (*(float *)(iVar5 + 0x48) < FLOAT_803e41c0)) {
      local_30 = (double)(longlong)(int)*(float *)(iVar5 + 0x50);
      iVar11 = (int)*(float *)(iVar12 + (uint)*(byte *)(iVar12 + 0x104) * 0xc + 0x50);
      local_38 = (double)(longlong)iVar11;
      if ((int)*(float *)(iVar5 + 0x50) == iVar11) {
        *(char *)(iVar12 + 0x105) = (char)uVar10;
      }
    }
    if ((uVar10 != *(byte *)(iVar12 + 0x102)) && (*(float *)(iVar5 + 0x50) < FLOAT_803e41c0)) {
      local_30 = (double)(longlong)(int)*(float *)(iVar5 + 0x48);
      iVar11 = (int)*(float *)(iVar12 + (uint)*(byte *)(iVar12 + 0x102) * 0xc + 0x48);
      local_38 = (double)(longlong)iVar11;
      if ((int)*(float *)(iVar5 + 0x48) == iVar11) {
        *(char *)(iVar12 + 0x103) = (char)uVar10;
      }
    }
    iVar5 = iVar5 + 0xc;
  }
  *(undefined *)(iVar12 + 0x146) = 1;
  sVar2 = psVar3[0x23];
  if (sVar2 == 0x411) {
    FUN_80174f2c((int)psVar3,iVar12);
    goto LAB_801773d0;
  }
  if (sVar2 < 0x411) {
    if (sVar2 == 0x21e) {
      FUN_80174f2c((int)psVar3,iVar12);
      goto LAB_801773d0;
    }
    if ((sVar2 < 0x21e) && (sVar2 == 0x1cb)) {
      if ((-1 < *(short *)(iVar7 + 0x18)) &&
         (uVar10 = FUN_80020078((int)*(short *)(iVar7 + 0x18)), uVar10 != 0)) {
        *(ushort *)(iVar12 + 0x100) = *(ushort *)(iVar12 + 0x100) | 0x81;
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        FUN_800e82d8((int)psVar3);
      }
      *(undefined *)(iVar12 + 0x146) = 0;
      goto LAB_801773d0;
    }
  }
  else if (sVar2 == 0x7df) {
    FUN_80174a34((int)psVar3,iVar12);
    goto LAB_801773d0;
  }
  if ((-1 < *(short *)(iVar7 + 0x18)) &&
     (uVar10 = FUN_80020078((int)*(short *)(iVar7 + 0x18)), uVar10 != 0)) {
    *(ushort *)(iVar12 + 0x100) = *(ushort *)(iVar12 + 0x100) | 1;
  }
LAB_801773d0:
  iVar5 = *(int *)(psVar3 + 0x32);
  if (iVar5 != 0) {
    *(uint *)(iVar5 + 0x30) = *(uint *)(iVar5 + 0x30) | 0xa10;
    *(undefined *)(*(int *)(psVar3 + 0x32) + 0x3a) = 0x60;
    *(undefined *)(*(int *)(psVar3 + 0x32) + 0x3b) = 0x40;
  }
  *(ushort *)(iVar12 + 0x100) = *(ushort *)(iVar12 + 0x100) | 0x40;
  iVar5 = FUN_80080100((int *)&DAT_803ad340,DAT_803de738,*(int *)(iVar7 + 0x14));
  if (iVar5 != -1) {
    *(ushort *)(iVar12 + 0x100) = *(ushort *)(iVar12 + 0x100) | 1;
    FUN_80080090((int *)&DAT_803ad340,&DAT_803de738,*(int *)(iVar7 + 0x14));
  }
  FUN_80286888();
  return;
}

