// Function: FUN_8011297c
// Entry: 8011297c
// Size: 840 bytes

void FUN_8011297c(void)

{
  ushort uVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int in_r7;
  float *pfVar8;
  int in_r8;
  undefined4 *puVar9;
  undefined2 in_r9;
  float *pfVar10;
  int in_r10;
  int iVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar17;
  float local_48;
  undefined4 local_44;
  float local_40;
  int local_3c;
  uint local_38;
  undefined4 local_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar17 = FUN_80286830();
  uVar4 = (uint)((ulonglong)uVar17 >> 0x20);
  iVar7 = (int)uVar17;
  iVar12 = *(int *)(uVar4 + 0xb8);
  iVar11 = in_r10;
  iVar5 = FUN_8002bac4();
  fVar2 = FLOAT_803e28ac;
  dVar16 = (double)*(float *)(iVar12 + 1000);
  dVar15 = (double)FLOAT_803e28ac;
  if (dVar15 < dVar16) {
    *(float *)(iVar12 + 1000) =
         (float)((double)FLOAT_803dc074 * (double)*(float *)(iVar12 + 0x3ec) + dVar16);
    uVar1 = *(ushort *)(iVar12 + 0x400);
    if ((uVar1 & 0x20) == 0) {
      if ((uVar1 & 0x40) == 0) {
        dVar13 = (double)*(float *)(iVar12 + 1000);
        if (dVar15 <= dVar13) {
          dVar14 = (double)FLOAT_803e28c4;
          if (dVar14 < dVar13) {
            *(float *)(iVar12 + 1000) = (float)(dVar14 - (double)(float)(dVar13 - dVar14));
            *(float *)(iVar12 + 0x3ec) = -*(float *)(iVar12 + 0x3ec);
          }
        }
        else {
          *(float *)(iVar12 + 1000) = fVar2;
        }
      }
      else if (FLOAT_803e28c0 < *(float *)(iVar12 + 1000)) {
        iVar6 = *(int *)(uVar4 + 0x4c);
        *(float *)(iVar12 + 1000) = fVar2;
        *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) & 0xffbf;
        *(undefined *)(iVar7 + 0x354) = 0;
        *(undefined *)(uVar4 + 0x36) = 0;
        *(undefined4 *)(uVar4 + 0xf4) = 1;
        *(ushort *)(uVar4 + 6) = *(ushort *)(uVar4 + 6) | 0x4000;
        uStack_2c = *(short *)(iVar6 + 0x2c) * 0x3c ^ 0x80000000;
        local_30 = 0x43300000;
        (**(code **)(*DAT_803dd72c + 100))
                  ((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e28b0),
                   *(undefined4 *)(iVar6 + 0x14));
      }
    }
    else {
      *(ushort *)(iVar12 + 0x400) = uVar1 & 0xffdf;
      *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) | 0x40;
      if (FLOAT_803e28c0 < *(float *)(iVar12 + 1000)) {
        *(float *)(iVar12 + 1000) = fVar2;
        *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) & 0xffbf;
      }
    }
  }
  if (*(char *)(iVar7 + 0x354) != '\0') {
    pfVar8 = &local_40;
    puVar9 = &local_44;
    pfVar10 = &local_48;
    iVar6 = FUN_80036868(uVar4,&local_3c,&local_34,&local_38,pfVar8,puVar9,pfVar10);
    *(undefined *)(iVar12 + 0x40a) = (undefined)local_34;
    if (iVar6 != 0) {
      if (in_r10 != 0) {
        *(float *)(in_r10 + 0xc) = local_40 + FLOAT_803dda58;
        *(undefined4 *)(in_r10 + 0x10) = local_44;
        *(float *)(in_r10 + 0x14) = local_48 + FLOAT_803dda5c;
      }
      if (in_r8 == 0) {
        local_38 = 0;
      }
      else {
        uVar3 = (uint)*(char *)(in_r8 + iVar6 + -2);
        if (uVar3 != 0xffffffff) {
          local_38 = uVar3;
        }
      }
      *(char *)(iVar7 + 0x354) = *(char *)(iVar7 + 0x354) - (char)local_38;
      if (*(char *)(iVar7 + 0x354) < '\x01') {
        *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) | 0x20;
        *(float *)(iVar12 + 1000) = FLOAT_803e28c8;
        *(float *)(iVar12 + 0x3ec) = FLOAT_803e28cc;
        *(undefined2 *)(iVar7 + 0x270) = in_r9;
        *(undefined *)(iVar7 + 0x354) = 0;
      }
      else if (local_38 != 0) {
        if ((*(int *)(iVar7 + 0x2d0) == 0) && (uVar3 = FUN_80296164(iVar5,1), uVar3 != 0)) {
          *(int *)(iVar7 + 0x2d0) = iVar5;
          *(undefined *)(iVar7 + 0x349) = 0;
        }
        *(float *)(iVar12 + 1000) = FLOAT_803e28c8;
        *(float *)(iVar12 + 0x3ec) = FLOAT_803e28d0;
        if ((in_r7 != 0) && (*(int *)(in_r7 + iVar6 * 4 + -8) != -1)) {
          (**(code **)(*DAT_803dd70c + 0x14))(uVar4,iVar7);
          *(undefined2 *)(iVar7 + 0x270) = in_r9;
        }
        *(char *)(iVar7 + 0x34f) = (char)iVar6;
      }
      uVar17 = FUN_8000b7dc(uVar4,0x10);
      FUN_800379bc(uVar17,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,local_3c,0xe0001,uVar4,0,
                   pfVar8,puVar9,pfVar10,iVar11);
    }
  }
  FUN_8028687c();
  return;
}

