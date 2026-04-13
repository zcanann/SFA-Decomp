// Function: FUN_8001bf44
// Entry: 8001bf44
// Size: 1836 bytes

void FUN_8001bf44(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined2 uVar1;
  undefined2 uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  ushort *puVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  undefined8 uVar13;
  uint local_88;
  uint local_84;
  int local_80;
  int iStack_7c;
  int local_78;
  int local_74;
  int local_70;
  int local_6c;
  undefined4 local_68;
  undefined4 local_64;
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
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar13 = FUN_80286834();
  puVar7 = (ushort *)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  uVar1 = *(undefined2 *)(param_3 + 0x18);
  uVar2 = *(undefined2 *)(param_3 + 0x1a);
  if ((*(ushort *)(param_3 + 0x1c) & 1) == 0) {
    *(ushort *)(param_3 + 0x1c) = *(ushort *)(param_3 + 0x1c) | 1;
    switch(*(undefined *)(param_3 + 0x13)) {
    case 0:
      uStack_24 = (int)*(short *)(param_3 + 0x14) ^ 0x80000000;
      local_28 = 0x43300000;
      uStack_2c = (int)*(short *)(param_3 + 0x16) ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df3c8),
                   DAT_803dd6a8,0xff,0x100,(uint)*(ushort *)(param_3 + 8),
                   (uint)*(ushort *)(param_3 + 10),0);
      break;
    case 1:
      local_68 = DAT_803df3c0;
      FUN_80075534((int)*(short *)(param_3 + 0x14),(int)*(short *)(param_3 + 0x16),
                   (int)*(short *)(param_3 + 0x14) + (uint)*(ushort *)(param_3 + 8),
                   (int)*(short *)(param_3 + 0x16) + (uint)*(ushort *)(param_3 + 10),&local_68);
      break;
    case 2:
      uVar11 = (uint)*(short *)(param_3 + 0x14);
      uVar10 = (uint)*(ushort *)(param_3 + 8);
      iVar8 = (int)*(short *)(param_3 + 0x16);
      uVar12 = (int)uVar10 >> 1;
      if (0xc < uVar12) {
        uVar12 = 0xc;
      }
      iVar9 = uVar10 + uVar12 * -2;
      if (iVar9 < 0) {
        iVar9 = 0;
      }
      FUN_8025da88(0,0,0x280,0x1e0);
      uStack_24 = uVar11 - 0x34 ^ 0x80000000;
      local_28 = 0x43300000;
      uStack_2c = iVar8 - 0x23U ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df3c8),
                   DAT_8033caa0,(uint)*(byte *)(param_3 + 0x1e),0x100);
      uStack_34 = uVar11 + uVar10 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack_3c = iVar8 - 0x23U ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df3c8),
                   DAT_8033cab0,(uint)*(byte *)(param_3 + 0x1e),0x100);
      if (uVar12 != 0) {
        uStack_24 = uVar11 ^ 0x80000000;
        local_28 = 0x43300000;
        uStack_2c = iVar8 - 0x13U ^ 0x80000000;
        local_30 = 0x43300000;
        FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df3c8),
                     (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df3c8),
                     DAT_8033caa4,(uint)*(byte *)(param_3 + 0x1e),0x100,uVar12,0x3a,0);
        uStack_34 = (uVar11 + uVar10) - uVar12 ^ 0x80000000;
        local_38 = 0x43300000;
        uStack_3c = iVar8 - 0x13U ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_80076144((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df3c8),
                     (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df3c8),
                     DAT_8033caac,(uint)*(byte *)(param_3 + 0x1e),0x100,uVar12,0x3a,0xc - uVar12,0);
      }
      if (iVar9 != 0) {
        uStack_24 = uVar11 + uVar12 ^ 0x80000000;
        local_28 = 0x43300000;
        uStack_2c = iVar8 - 0x13U ^ 0x80000000;
        local_30 = 0x43300000;
        FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df3c8),
                     (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df3c8),
                     DAT_8033caa8,(uint)*(byte *)(param_3 + 0x1e),0x100,iVar9,0x3a,0);
      }
      break;
    case 3:
      iVar9 = FUN_80017414();
      if (puVar7 == (ushort *)0x0) {
        if (iVar8 != 0) {
          uVar10 = param_3 + 0x7fd38480;
          FUN_800164e8(iVar8,((int)uVar10 >> 5) + (uint)((int)uVar10 < 0 && (uVar10 & 0x1f) != 0),
                       (int *)&local_88,(int *)&local_84,&local_80,&iStack_7c);
        }
      }
      else {
        FUN_800162c4((uint)*puVar7,0,0,(int *)&local_88,(int *)&local_84,&local_80,&iStack_7c);
      }
      FUN_8001746c(iVar9);
      uStack_24 = local_88 - 0x16 ^ 0x80000000;
      local_28 = 0x43300000;
      uStack_2c = local_80 - 9U ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df3c8),
                   DAT_8033cab4,(uint)*(byte *)(param_3 + 0x1e),0x100);
      uStack_34 = local_88 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack_3c = local_80 - 9U ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df3c8),
                   DAT_8033cab8,(uint)*(byte *)(param_3 + 0x1e),0x100,local_84 - local_88,0x24,0);
      uStack_44 = local_84 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_4c = local_80 - 9U ^ 0x80000000;
      local_50 = 0x43300000;
      FUN_80077318((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df3c8),
                   DAT_8033cabc,(uint)*(byte *)(param_3 + 0x1e),0x100);
      break;
    case 4:
      FUN_8001c670(puVar7,iVar8,param_3);
      break;
    case 5:
      goto LAB_8001c658;
    case 6:
      if (puVar7 == (ushort *)0x0) goto LAB_8001c658;
      iVar9 = FUN_80017414();
      if (puVar7 == (ushort *)0x0) {
        if (iVar8 != 0) {
          uVar10 = param_3 + 0x7fd38480;
          FUN_800164e8(iVar8,((int)uVar10 >> 5) + (uint)((int)uVar10 < 0 && (uVar10 & 0x1f) != 0),
                       &local_78,&local_74,&local_70,&local_6c);
        }
      }
      else {
        FUN_800162c4((uint)*puVar7,0,0,&local_78,&local_74,&local_70,&local_6c);
      }
      FUN_8001746c(iVar9);
      iVar8 = local_74 - local_78 >> 1;
      iVar9 = local_6c - local_70 >> 1;
      uVar10 = local_78 + iVar8;
      uVar11 = local_70 + iVar9;
      uStack_5c = local_78 - DAT_803dc04c ^ 0x80000000;
      local_60 = 0x43300000;
      uStack_54 = local_70 - DAT_803dc04c ^ 0x80000000;
      local_58 = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df3c8),
                   DAT_803dd6a4,0xff,0x100,iVar8 + DAT_803dc04c,iVar9 + DAT_803dc04c,0);
      uStack_4c = uVar10 ^ 0x80000000;
      local_50 = 0x43300000;
      uStack_44 = local_70 - DAT_803dc04c ^ 0x80000000;
      local_48 = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df3c8),
                   DAT_803dd6a4,0xff,0x100,iVar8 + DAT_803dc04c,iVar9 + DAT_803dc04c,1);
      uStack_3c = local_78 - DAT_803dc04c ^ 0x80000000;
      local_40 = 0x43300000;
      uStack_34 = uVar11 ^ 0x80000000;
      local_38 = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df3c8),
                   DAT_803dd6a4,0xff,0x100,iVar8 + DAT_803dc04c,iVar9 + DAT_803dc04c,2);
      uStack_2c = uVar10 ^ 0x80000000;
      local_30 = 0x43300000;
      uStack_24 = uVar11 ^ 0x80000000;
      local_28 = 0x43300000;
      FUN_80076998((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df3c8),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df3c8),
                   DAT_803dd6a4,0xff,0x100,iVar8 + DAT_803dc04c,iVar9 + DAT_803dc04c,3);
      break;
    case 7:
      iVar8 = FUN_80019c28();
      if (iVar8 == 3) {
        local_64 = DAT_803df3c0;
        FUN_80075534((int)*(short *)(param_3 + 0x14),(int)*(short *)(param_3 + 0x16),
                     (int)*(short *)(param_3 + 0x14) + (uint)*(ushort *)(param_3 + 8),
                     (int)*(short *)(param_3 + 0x16) + (uint)*(ushort *)(param_3 + 10),&local_64);
      }
      else {
        sVar5 = *(short *)(param_3 + 10);
        sVar6 = *(short *)(param_3 + 8);
        sVar3 = *(short *)(param_3 + 0x16);
        sVar4 = *(short *)(param_3 + 0x14);
        FUN_8025da88(0,0,0x280,0x1e0);
        FUN_8012c9e8((int)(short)(sVar4 + -4),(int)(short)(sVar3 + -4),sVar6 + 8,sVar5 + 8,0xff,1);
      }
    }
    *(undefined2 *)(param_3 + 0x18) = uVar1;
    *(undefined2 *)(param_3 + 0x1a) = uVar2;
  }
LAB_8001c658:
  FUN_80286880();
  return;
}

