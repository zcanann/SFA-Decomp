// Function: FUN_80126188
// Entry: 80126188
// Size: 1064 bytes

/* WARNING: Removing unreachable block (ram,0x80126590) */
/* WARNING: Removing unreachable block (ram,0x80126198) */

void FUN_80126188(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  ushort uVar9;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar10;
  byte bVar11;
  undefined8 uVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f31;
  double dVar15;
  double in_ps31_1;
  undefined4 local_58;
  undefined local_54;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_8028682c();
  iVar3 = FUN_8022de2c();
  local_58 = DAT_803e2a88;
  local_54 = DAT_803e2a8c;
  if (iVar3 != 0) {
    if (DAT_803de44c == '\0') {
      local_40 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
      uStack_44 = (int)DAT_803de4b8 ^ 0x80000000;
      iVar7 = (int)-(FLOAT_803e2c20 * (float)(local_40 - DOUBLE_803e2b08) -
                    (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8));
      local_50 = (double)(longlong)iVar7;
      DAT_803de4b8 = (short)iVar7;
      if (DAT_803de4b8 < 0) {
        DAT_803de4b8 = 0;
      }
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
      uStack_44 = (int)DAT_803de4b8 ^ 0x80000000;
      iVar7 = (int)(FLOAT_803e2c20 * (float)(local_50 - DOUBLE_803e2b08) +
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8));
      local_40 = (double)(longlong)iVar7;
      DAT_803de4b8 = (short)iVar7;
      if (0xff < DAT_803de4b8) {
        DAT_803de4b8 = 0xff;
      }
    }
    local_48 = 0x43300000;
    dVar14 = (double)FLOAT_803e2c20;
    uVar4 = FUN_8022dc54(iVar3);
    iVar5 = FUN_8022dc44(iVar3);
    iVar6 = FUN_8022dc38(iVar3);
    iVar7 = FUN_8022dbd8(iVar3);
    iVar8 = FUN_8022dbcc(iVar3);
    if (iVar8 < iVar7) {
      iVar7 = iVar8;
    }
    dVar13 = DOUBLE_803e2af8;
    for (uVar10 = 0; uVar1 = uVar10 & 0xff, (int)uVar1 < iVar5 >> 2; uVar10 = uVar10 + 1) {
      if ((int)uVar1 < (int)uVar4 >> 2) {
        iVar2 = 0x16;
      }
      else {
        iVar2 = (uVar4 & 3) + 0x12;
        if ((int)uVar4 >> 2 < (int)uVar1) {
          iVar2 = 0x12;
        }
      }
      local_40 = (double)CONCAT44(0x43300000,uVar1 * 0x21 + 0x1e ^ 0x80000000);
      FUN_80077318((double)(float)(local_40 - dVar13),(double)FLOAT_803e2c2c,(&DAT_803a9610)[iVar2],
                   (int)DAT_803de4b8 & 0xff,0x100);
    }
    dVar13 = DOUBLE_803e2af8;
    for (bVar11 = 0; bVar11 < 3; bVar11 = bVar11 + 1) {
      iVar5 = (uint)bVar11 * 0x1c;
      local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x1eU ^ 0x80000000);
      FUN_80077318((double)(float)(local_40 - dVar13),(double)FLOAT_803e2ce0,DAT_803a96f0,
                   (int)DAT_803de4b8 & 0xff,0x100);
      if ((int)(uint)bVar11 < iVar6) {
        local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x23U ^ 0x80000000);
        FUN_80077318((double)(float)(local_40 - DOUBLE_803e2af8),(double)FLOAT_803e2ce4,DAT_803a96f4
                     ,(int)DAT_803de4b8 & 0xff,0x100);
      }
    }
    if (*(char *)(iVar3 + 0xac) != '&') {
      FUN_80077318((double)FLOAT_803e2ce8,(double)FLOAT_803e2c2c,DAT_803a9704,
                   (int)DAT_803de4b8 & 0xff,0x100);
      dVar13 = DOUBLE_803e2af8;
      for (uVar4 = 0; dVar15 = DOUBLE_803e2af8, (int)(uVar4 & 0xff) < iVar7; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,(uVar4 & 0xff) * -0x14 + 0x244 ^ 0x80000000);
        FUN_80077318((double)(float)(local_40 - dVar13),(double)FLOAT_803e2c1c,DAT_803a9700,
                     (int)DAT_803de4b8 & 0xff,0x100);
      }
      for (; uVar10 = uVar4 & 0xff, (int)uVar10 < iVar8; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x244 ^ 0x80000000);
        FUN_80077318((double)(float)(local_40 - dVar15),(double)FLOAT_803e2c1c,DAT_803a96fc,
                     (int)DAT_803de4b8 & 0xff,0x100);
      }
      local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x23c ^ 0x80000000);
      dVar13 = (double)FLOAT_803e2c2c;
      uVar12 = FUN_80077318((double)(float)(local_40 - DOUBLE_803e2af8),dVar13,DAT_803a96f8,
                            (int)DAT_803de4b8 & 0xff,0x100);
      uVar9 = FUN_8022dc14(iVar3);
      FUN_8028fde8(uVar12,dVar13,dVar14,in_f4,in_f5,in_f6,in_f7,in_f8,(int)&local_58,&DAT_803dc7c8,
                   (uint)uVar9,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    FUN_80019940(0xff,0xff,0xff,(byte)DAT_803de4b8);
    FUN_80015e00(&local_58,0x93,0x23a,0x41);
    FUN_80125708();
  }
  FUN_80286878();
  return;
}

