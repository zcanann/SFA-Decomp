// Function: FUN_801769b4
// Entry: 801769b4
// Size: 1552 bytes

/* WARNING: Removing unreachable block (ram,0x80176fa4) */

void FUN_801769b4(void)

{
  char cVar1;
  byte bVar2;
  short sVar3;
  bool bVar4;
  short *psVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  undefined8 uVar17;
  float local_48;
  float local_44;
  float local_40;
  double local_38;
  double local_30;
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar17 = FUN_802860d8();
  psVar5 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar8 = (int)uVar17;
  if (*(int *)(iVar8 + 0x14) == 0x30398) {
    *(undefined *)(iVar8 + 0x23) = 1;
  }
  else {
    *(undefined *)(iVar8 + 0x23) = 0xff;
  }
  *psVar5 = (ushort)*(byte *)(iVar8 + 0x22) << 8;
  *(float *)(psVar5 + 8) = FLOAT_803e358c + *(float *)(iVar8 + 0xc);
  FUN_80037200(psVar5,5);
  FUN_8002b8c8(psVar5,0x5a);
  *(code **)(psVar5 + 0x5e) = FUN_8017510c;
  iVar11 = *(int *)(psVar5 + 0x5c);
  *(undefined *)(iVar11 + 0xb4) = 0;
  piVar9 = *(int **)(*(int *)(psVar5 + 0x3e) + *(char *)((int)psVar5 + 0xad) * 4);
  iVar10 = *piVar9;
  *(undefined4 *)(iVar11 + 0xb0) = *(undefined4 *)(iVar8 + 0x1c);
  local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar8 + 0x20));
  *(float *)(iVar11 + 0x10) = (float)(local_38 - DOUBLE_803e35d0) / FLOAT_803e35cc;
  *(float *)(iVar11 + 0x10) = *(float *)(iVar11 + 0x10) * *(float *)(*(int *)(psVar5 + 0x28) + 4);
  uVar6 = FUN_80028434(*piVar9);
  local_30 = (double)CONCAT44(0x43300000,uVar6 & 0xffff);
  *(float *)(iVar11 + 0xc) =
       *(float *)(iVar11 + 0x10) * (float)(local_30 - DOUBLE_803e35d0) + FLOAT_803e3558;
  *(float *)(iVar11 + 0x14) = FLOAT_803e3528;
  *(undefined2 *)(iVar11 + 0xac) = *(undefined2 *)(iVar8 + 0x18);
  FUN_80030334(psVar5,0,0);
  FUN_80037964(psVar5,4);
  FUN_80035f20(psVar5);
  dVar16 = (double)FLOAT_803e3540;
  for (iVar12 = 0; iVar12 < (int)(uint)*(ushort *)(iVar10 + 0xe4); iVar12 = iVar12 + 1) {
    FUN_80026e00(iVar10,iVar12,&local_48);
    if ((double)local_44 < dVar16) {
      dVar16 = (double)local_44;
    }
  }
  for (iVar12 = 0; iVar12 < (int)(uint)*(ushort *)(iVar10 + 0xe4); iVar12 = iVar12 + 1) {
    FUN_80026e00(iVar10,iVar12,&local_48);
    if ((double)local_44 == dVar16) {
      bVar4 = false;
      cVar1 = *(char *)(iVar11 + 0xb4);
      for (iVar13 = 0; iVar13 < cVar1; iVar13 = iVar13 + 1) {
        iVar7 = iVar11 + iVar13 * 0xc;
        if ((local_48 == *(float *)(iVar7 + 0x48)) && (local_40 == *(float *)(iVar7 + 0x50))) {
          bVar4 = true;
          iVar13 = (int)cVar1;
        }
      }
      if (!bVar4) {
        *(float *)(iVar11 + cVar1 * 0xc + 0x48) = local_48;
        *(float *)(iVar11 + *(char *)(iVar11 + 0xb4) * 0xc + 0x4c) = local_44;
        *(float *)(iVar11 + *(char *)(iVar11 + 0xb4) * 0xc + 0x50) = local_40;
        *(char *)(iVar11 + 0xb4) = *(char *)(iVar11 + 0xb4) + '\x01';
      }
    }
  }
  if ('\x04' < *(char *)(iVar11 + 0xb4)) {
    *(undefined *)(iVar11 + 0xb4) = 4;
    FUN_801378a8(s_PUSHPULL_OBJECT__hitpoint_overfl_80320d90);
  }
  iVar12 = *(int *)(psVar5 + 0x2c);
  bVar2 = *(byte *)(iVar12 + 0x10c);
  dVar16 = (double)FLOAT_803e3528;
  iVar10 = iVar11;
  for (iVar13 = 0; iVar13 < *(char *)(iVar11 + 0xb4); iVar13 = iVar13 + 1) {
    *(undefined4 *)(iVar10 + 0x18) = *(undefined4 *)(iVar10 + 0x48);
    *(undefined4 *)(iVar10 + 0x1c) = *(undefined4 *)(iVar10 + 0x4c);
    *(undefined4 *)(iVar10 + 0x20) = *(undefined4 *)(iVar10 + 0x50);
    dVar15 = (double)*(float *)(iVar10 + 0x18);
    if (dVar16 <= dVar15) {
      *(float *)(iVar10 + 0x18) = (float)(dVar15 - (double)FLOAT_803e358c);
    }
    else {
      *(float *)(iVar10 + 0x18) = (float)(dVar15 + (double)FLOAT_803e358c);
    }
    dVar15 = (double)*(float *)(iVar10 + 0x20);
    if (dVar16 <= dVar15) {
      *(float *)(iVar10 + 0x20) = (float)(dVar15 - (double)FLOAT_803e358c);
    }
    else {
      *(float *)(iVar10 + 0x20) = (float)(dVar15 + (double)FLOAT_803e358c);
    }
    dVar15 = (double)*(float *)(iVar10 + 0x48);
    if (dVar16 <= dVar15) {
      *(float *)(iVar10 + 0x48) = (float)(dVar15 - (double)FLOAT_803e3588);
      *(char *)(iVar11 + 0x104) = (char)iVar13;
    }
    else {
      *(float *)(iVar10 + 0x48) = (float)(dVar15 + (double)FLOAT_803e3588);
    }
    dVar15 = (double)*(float *)(iVar10 + 0x50);
    if (dVar16 <= dVar15) {
      *(float *)(iVar10 + 0x50) = (float)(dVar15 - (double)FLOAT_803e3588);
      *(char *)(iVar11 + 0x102) = (char)iVar13;
    }
    else {
      *(float *)(iVar10 + 0x50) = (float)(dVar15 + (double)FLOAT_803e3588);
    }
    FUN_800226cc((double)*(float *)(iVar10 + 0x18),(double)*(float *)(iVar10 + 0x1c),
                 (double)*(float *)(iVar10 + 0x20),iVar12 + (bVar2 + 2) * 0x40,iVar10 + 0x78,
                 iVar10 + 0x7c,iVar10 + 0x80);
    iVar10 = iVar10 + 0xc;
  }
  iVar10 = iVar11;
  for (uVar6 = 0; (int)uVar6 < (int)*(char *)(iVar11 + 0xb4); uVar6 = uVar6 + 1) {
    if ((uVar6 != *(byte *)(iVar11 + 0x104)) && (*(float *)(iVar10 + 0x48) < FLOAT_803e3528)) {
      local_30 = (double)(longlong)(int)*(float *)(iVar10 + 0x50);
      iVar12 = (int)*(float *)(iVar11 + (uint)*(byte *)(iVar11 + 0x104) * 0xc + 0x50);
      local_38 = (double)(longlong)iVar12;
      if ((int)*(float *)(iVar10 + 0x50) == iVar12) {
        *(char *)(iVar11 + 0x105) = (char)uVar6;
      }
    }
    if ((uVar6 != *(byte *)(iVar11 + 0x102)) && (*(float *)(iVar10 + 0x50) < FLOAT_803e3528)) {
      local_30 = (double)(longlong)(int)*(float *)(iVar10 + 0x48);
      iVar12 = (int)*(float *)(iVar11 + (uint)*(byte *)(iVar11 + 0x102) * 0xc + 0x48);
      local_38 = (double)(longlong)iVar12;
      if ((int)*(float *)(iVar10 + 0x48) == iVar12) {
        *(char *)(iVar11 + 0x103) = (char)uVar6;
      }
    }
    iVar10 = iVar10 + 0xc;
  }
  *(undefined *)(iVar11 + 0x146) = 1;
  sVar3 = psVar5[0x23];
  if (sVar3 == 0x411) {
    FUN_80174a80(psVar5,iVar11);
    goto LAB_80176f24;
  }
  if (sVar3 < 0x411) {
    if (sVar3 == 0x21e) {
      FUN_80174a80(psVar5,iVar11);
      goto LAB_80176f24;
    }
    if ((sVar3 < 0x21e) && (sVar3 == 0x1cb)) {
      if ((-1 < *(short *)(iVar8 + 0x18)) && (iVar10 = FUN_8001ffb4(), iVar10 != 0)) {
        *(ushort *)(iVar11 + 0x100) = *(ushort *)(iVar11 + 0x100) | 0x81;
        *(byte *)((int)psVar5 + 0xaf) = *(byte *)((int)psVar5 + 0xaf) | 8;
        FUN_800e8054(psVar5);
      }
      *(undefined *)(iVar11 + 0x146) = 0;
      goto LAB_80176f24;
    }
  }
  else if (sVar3 == 0x7df) {
    FUN_80174588(psVar5,iVar11);
    goto LAB_80176f24;
  }
  if ((-1 < *(short *)(iVar8 + 0x18)) && (iVar10 = FUN_8001ffb4(), iVar10 != 0)) {
    *(ushort *)(iVar11 + 0x100) = *(ushort *)(iVar11 + 0x100) | 1;
  }
LAB_80176f24:
  iVar10 = *(int *)(psVar5 + 0x32);
  if (iVar10 != 0) {
    *(uint *)(iVar10 + 0x30) = *(uint *)(iVar10 + 0x30) | 0xa10;
    *(undefined *)(*(int *)(psVar5 + 0x32) + 0x3a) = 0x60;
    *(undefined *)(*(int *)(psVar5 + 0x32) + 0x3b) = 0x40;
  }
  *(ushort *)(iVar11 + 0x100) = *(ushort *)(iVar11 + 0x100) | 0x40;
  iVar10 = FUN_8007fe74(&DAT_803ac6e0,DAT_803ddab8,*(undefined4 *)(iVar8 + 0x14));
  if (iVar10 != -1) {
    *(ushort *)(iVar11 + 0x100) = *(ushort *)(iVar11 + 0x100) | 1;
    FUN_8007fe04(&DAT_803ac6e0,&DAT_803ddab8,*(undefined4 *)(iVar8 + 0x14));
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  FUN_80286124();
  return;
}

