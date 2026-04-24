// Function: FUN_8011faa8
// Entry: 8011faa8
// Size: 1092 bytes

/* WARNING: Removing unreachable block (ram,0x8011fec4) */
/* WARNING: Removing unreachable block (ram,0x8011febc) */
/* WARNING: Removing unreachable block (ram,0x8011fac0) */
/* WARNING: Removing unreachable block (ram,0x8011fab8) */

void FUN_8011faa8(void)

{
  byte bVar1;
  int iVar2;
  short sVar3;
  ushort uVar4;
  int iVar5;
  int iVar6;
  char cVar7;
  uint uVar8;
  double dVar9;
  double dVar10;
  int local_78;
  int local_74;
  int local_70;
  int local_6c [3];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  
  iVar5 = FUN_8002bac4();
  iVar2 = DAT_803de450;
  if (DAT_803de450 != 0) {
    bVar1 = *(byte *)(DAT_803de450 + 0x18);
    if ((((*(char *)(DAT_803de450 + 0x44) < '\0') || (DAT_803de400 != '\0')) ||
        (iVar6 = FUN_80020800(), iVar6 != 0)) ||
       (((iVar5 != 0 && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) != 0)) &&
        (*(short *)(iVar2 + 0x2c) != 0x5d5)))) {
      sVar3 = (ushort)bVar1 + (ushort)DAT_803dc070 * -4;
      if (sVar3 < 0) {
        sVar3 = 0;
      }
      *(char *)(iVar2 + 0x18) = (char)sVar3;
      if ((*(char *)(iVar2 + 0x18) == '\0') && ((char)*(byte *)(iVar2 + 0x44) < '\0')) {
        *(byte *)(iVar2 + 0x44) = *(byte *)(iVar2 + 0x44) & 0x7f;
        FUN_8011fa10();
        return;
      }
    }
    else {
      uVar4 = (ushort)bVar1 + (ushort)DAT_803dc070 * 4;
      if (0xff < uVar4) {
        uVar4 = 0xff;
      }
      *(char *)(iVar2 + 0x18) = (char)uVar4;
    }
    FUN_8025db38(local_6c,&local_70,&local_74,&local_78);
    FUN_8025da88(0,0,0x280,0x1e0);
    iVar5 = *(int *)(iVar2 + 0x40);
    if (iVar5 == 1) {
      uVar4 = *(ushort *)(iVar2 + 0x2c);
      if (uVar4 == 0x643) {
        cVar7 = -0xc;
      }
      else if ((uVar4 < 0x643) && (uVar4 == 0x63e)) {
        cVar7 = -10;
      }
      else {
        cVar7 = '\0';
      }
      uStack_5c = (int)DAT_803de479 + 0xb5U ^ 0x80000000;
      local_60 = 0x43300000;
      local_6c[2] = (0x1a4 - (uint)(*(ushort *)(*(int *)(iVar2 + 0x30) + 0xc) >> 1)) +
                    (int)DAT_803dc754 + (int)cVar7 + (int)DAT_803de478 ^ 0x80000000;
      local_6c[1] = 0x43300000;
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - DOUBLE_803e2af8),
                   *(int *)(iVar2 + 0x30),(uint)*(byte *)(iVar2 + 0x18),0x100);
      uVar8 = *(ushort *)(*(int *)(iVar2 + 0x30) + 10) + 0xb4;
      uStack_4c = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1);
      if (*(int *)(iVar2 + 8) < 0x9e) {
        *(uint *)(iVar2 + 8) = *(int *)(iVar2 + 8) + (uint)DAT_803dc070 * (uint)DAT_803dc755;
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
      uStack_5c = uVar8 + iVar5 ^ 0x80000000;
      local_60 = 0x43300000;
      local_6c[2] = uStack_4c ^ 0x80000000;
      local_6c[1] = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - DOUBLE_803e2af8),
                   *(undefined4 *)(iVar2 + 0x3c),(uint)*(byte *)(iVar2 + 0x18),0x100,
                   *(int *)(iVar2 + 8) - iVar5,0x1a,0);
      uStack_54 = uVar8 ^ 0x80000000;
      local_58 = 0x43300000;
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2af8),
                   *(undefined4 *)(iVar2 + 0x38),(uint)*(byte *)(iVar2 + 0x18),0x100,iVar5,0x1a,0);
      uStack_44 = uVar8 + *(int *)(iVar2 + 8) ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_3c = 0x1a4 - (*(ushort *)(*(int *)(iVar2 + 0x34) + 0xc) >> 1) ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2af8),
                   *(int *)(iVar2 + 0x34),(uint)*(byte *)(iVar2 + 0x18),0x100);
    }
    else if ((iVar5 < 1) && (-1 < iVar5)) {
      uVar8 = 0x140 - ((uint)(*(int *)(iVar2 + 0x10) * *(int *)(iVar2 + 4)) >> 1);
      dVar9 = DOUBLE_803e2af8;
      dVar10 = DOUBLE_803e2b08;
      for (iVar5 = 0; iVar5 < *(int *)(iVar2 + 4); iVar5 = iVar5 + 1) {
        if (iVar5 < *(int *)(iVar2 + 0xc)) {
          iVar6 = *(int *)(iVar2 + 0x2c);
        }
        else {
          iVar6 = *(int *)(iVar2 + 0x30);
        }
        local_6c[2] = uVar8 ^ 0x80000000;
        local_6c[1] = 0x43300000;
        uStack_5c = 0x1a4 - *(int *)(iVar2 + 0x14);
        local_60 = 0x43300000;
        FUN_80077318((double)(float)((double)CONCAT44(0x43300000,local_6c[2]) - dVar9),
                     (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar10),iVar6,
                     (uint)*(byte *)(iVar2 + 0x18),0x100);
        uVar8 = uVar8 + *(int *)(iVar2 + 0x10);
      }
    }
    FUN_8025da88(local_6c[0],local_70,local_74,local_78);
  }
  return;
}

