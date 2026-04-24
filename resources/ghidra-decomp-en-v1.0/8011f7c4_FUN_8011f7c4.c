// Function: FUN_8011f7c4
// Entry: 8011f7c4
// Size: 1092 bytes

/* WARNING: Removing unreachable block (ram,0x8011fbd8) */
/* WARNING: Removing unreachable block (ram,0x8011fbe0) */

void FUN_8011f7c4(void)

{
  byte bVar1;
  int iVar2;
  short sVar3;
  ushort uVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  char cVar8;
  uint uVar9;
  undefined4 uVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar5 = FUN_8002b9ec();
  iVar2 = DAT_803dd7d0;
  if (DAT_803dd7d0 != 0) {
    bVar1 = *(byte *)(DAT_803dd7d0 + 0x18);
    if ((((*(char *)(DAT_803dd7d0 + 0x44) < '\0') || (DAT_803dd780 != '\0')) ||
        (iVar6 = FUN_8002073c(), iVar6 != 0)) ||
       (((iVar5 != 0 && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) != 0)) &&
        (*(short *)(iVar2 + 0x2c) != 0x5d5)))) {
      sVar3 = (ushort)bVar1 + (ushort)DAT_803db410 * -4;
      if (sVar3 < 0) {
        sVar3 = 0;
      }
      *(char *)(iVar2 + 0x18) = (char)sVar3;
      if ((*(char *)(iVar2 + 0x18) == '\0') && ((char)*(byte *)(iVar2 + 0x44) < '\0')) {
        *(byte *)(iVar2 + 0x44) = *(byte *)(iVar2 + 0x44) & 0x7f;
        FUN_8011f72c();
        goto LAB_8011fbd8;
      }
    }
    else {
      uVar4 = (ushort)bVar1 + (ushort)DAT_803db410 * 4;
      if (0xff < uVar4) {
        uVar4 = 0xff;
      }
      *(char *)(iVar2 + 0x18) = (char)uVar4;
    }
    FUN_8025d3d4(&local_6c,&local_70,&local_74,&local_78);
    FUN_8025d324(0,0,0x280,0x1e0);
    iVar5 = *(int *)(iVar2 + 0x40);
    if (iVar5 == 1) {
      uVar4 = *(ushort *)(iVar2 + 0x2c);
      if (uVar4 == 0x643) {
        cVar8 = -0xc;
      }
      else if ((uVar4 < 0x643) && (uVar4 == 0x63e)) {
        cVar8 = -10;
      }
      else {
        cVar8 = '\0';
      }
      uStack92 = (int)DAT_803dd7f9 + 0xb5U ^ 0x80000000;
      local_60 = 0x43300000;
      uStack100 = (0x1a4 - (uint)(*(ushort *)(*(int *)(iVar2 + 0x30) + 0xc) >> 1)) +
                  (int)DAT_803dbaec + (int)cVar8 + (int)DAT_803dd7f8 ^ 0x80000000;
      local_68 = 0x43300000;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e1e78),
                   *(int *)(iVar2 + 0x30),*(undefined *)(iVar2 + 0x18),0x100);
      uVar9 = *(ushort *)(*(int *)(iVar2 + 0x30) + 10) + 0xb4;
      uStack76 = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1);
      if (*(int *)(iVar2 + 8) < 0x9e) {
        *(uint *)(iVar2 + 8) = *(int *)(iVar2 + 8) + (uint)DAT_803db410 * (uint)DAT_803dbaed;
      }
      iVar5 = *(int *)(iVar2 + 0xc);
      if (iVar5 < 0) {
        iVar5 = 0;
      }
      else if (*(int *)(iVar2 + 8) < iVar5) {
        iVar5 = *(int *)(iVar2 + 8);
      }
      *(int *)(iVar2 + 0xc) = iVar5;
      iVar5 = (int)(short)iVar5;
      uStack92 = uVar9 + iVar5 ^ 0x80000000;
      local_60 = 0x43300000;
      uStack100 = uStack76 ^ 0x80000000;
      local_68 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e1e78),
                   *(undefined4 *)(iVar2 + 0x3c),*(undefined *)(iVar2 + 0x18),0x100,
                   *(int *)(iVar2 + 8) - iVar5,0x1a,0);
      uStack84 = uVar9 ^ 0x80000000;
      local_58 = 0x43300000;
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e1e78),
                   *(undefined4 *)(iVar2 + 0x38),*(undefined *)(iVar2 + 0x18),0x100,iVar5,0x1a,0);
      uStack68 = uVar9 + *(int *)(iVar2 + 8) ^ 0x80000000;
      local_48 = 0x43300000;
      uStack60 = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1) ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1e78),
                   *(int *)(iVar2 + 0x34),*(undefined *)(iVar2 + 0x18),0x100);
    }
    else if ((iVar5 < 1) && (-1 < iVar5)) {
      uVar9 = 0x140 - ((uint)(*(int *)(iVar2 + 0x10) * *(int *)(iVar2 + 4)) >> 1);
      dVar11 = DOUBLE_803e1e78;
      dVar12 = DOUBLE_803e1e88;
      for (iVar5 = 0; iVar5 < *(int *)(iVar2 + 4); iVar5 = iVar5 + 1) {
        if (iVar5 < *(int *)(iVar2 + 0xc)) {
          uVar7 = *(undefined4 *)(iVar2 + 0x2c);
        }
        else {
          uVar7 = *(undefined4 *)(iVar2 + 0x30);
        }
        uStack100 = uVar9 ^ 0x80000000;
        local_68 = 0x43300000;
        uStack92 = 0x1a4 - *(int *)(iVar2 + 0x14);
        local_60 = 0x43300000;
        FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack100) - dVar11),
                     (double)(float)((double)CONCAT44(0x43300000,uStack92) - dVar12),uVar7,
                     *(undefined *)(iVar2 + 0x18),0x100);
        uVar9 = uVar9 + *(int *)(iVar2 + 0x10);
      }
    }
    FUN_8025d324(local_6c,local_70,local_74,local_78);
  }
LAB_8011fbd8:
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  return;
}

