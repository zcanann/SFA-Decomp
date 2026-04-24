// Function: FUN_8018f2d8
// Entry: 8018f2d8
// Size: 2220 bytes

/* WARNING: Removing unreachable block (ram,0x8018fb64) */

void FUN_8018f2d8(void)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  short sVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  double dVar7;
  undefined2 local_68;
  undefined2 local_66;
  short local_64;
  undefined auStack96 [8];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = FUN_802860d8();
  iVar5 = *(int *)(iVar2 + 0xb8);
  local_58 = FLOAT_803e3e68;
  bVar1 = *(byte *)(iVar5 + 8);
  if (bVar1 == 0) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack52 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x14));
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3e60);
      uStack60 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x18));
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e3e60);
      uStack68 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x16));
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e3e60);
      local_68 = *(undefined2 *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80021ac8(&local_68,&local_54);
      local_54 = local_54 + *(float *)(iVar2 + 0xc);
      local_50 = local_50 + *(float *)(iVar2 + 0x10);
      local_4c = local_4c + *(float *)(iVar2 + 0x14);
      (**(code **)(*DAT_803dca88 + 8))
                (iVar2,*(undefined2 *)(iVar5 + 10),auStack96,0x200001,0xffffffff,0);
    }
    else {
      dVar7 = DOUBLE_803e3e60;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack68 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x14));
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack68) - dVar7);
        uStack60 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x18));
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack60) - dVar7);
        uStack52 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x16));
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack52) - dVar7);
        local_68 = *(undefined2 *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80021ac8(&local_68,&local_54);
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (**(code **)(*DAT_803dca88 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack96,0x200001,0xffffffff,0);
      }
    }
  }
  else if (bVar1 == 1) {
    piVar3 = (int *)FUN_80013ec8(*(short *)(iVar5 + 10) + 0x58,1);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
      }
    }
    FUN_80013e2c(piVar3);
  }
  else if (bVar1 == 2) {
    piVar3 = (int *)FUN_80013ec8(*(short *)(iVar5 + 10) + 0xab,1);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
      }
    }
    FUN_80013e2c(piVar3);
  }
  else if (bVar1 == 3) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack52 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x14));
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3e60);
      uStack60 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x18));
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e3e60);
      uStack68 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x16));
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e3e60);
      local_68 = *(undefined2 *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80021ac8(&local_68,&local_54);
      (**(code **)(*DAT_803dca88 + 8))(iVar2,*(undefined2 *)(iVar5 + 10),auStack96,2,0xffffffff,0);
    }
    else {
      dVar7 = DOUBLE_803e3e60;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack52 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x14));
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack52) - dVar7);
        uStack60 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x18));
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack60) - dVar7);
        uStack68 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x16));
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack68) - dVar7);
        local_68 = *(undefined2 *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80021ac8(&local_68,&local_54);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,*(undefined2 *)(iVar5 + 10),auStack96,2,0xffffffff,0)
        ;
      }
    }
  }
  else if (5 < bVar1) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack52 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x14));
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3e60);
      uStack60 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x18));
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e3e60);
      uStack68 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x16));
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e3e60);
      FUN_80021ac8(iVar5 + 0x1a,&local_54);
      if (*(char *)(iVar5 + 8) == '\x06') {
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (**(code **)(*DAT_803dca88 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack96,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dca88 + 8))(iVar2,*(undefined2 *)(iVar5 + 10),auStack96,2,0xffffffff,0)
        ;
      }
    }
    else {
      dVar7 = DOUBLE_803e3e60;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack52 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x14));
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack52) - dVar7);
        uStack60 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x18));
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack60) - dVar7);
        uStack68 = FUN_800221a0(-(uint)*(ushort *)(iVar5 + 0x16));
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack68) - dVar7);
        FUN_80021ac8(iVar5 + 0x1a,&local_54);
        if (*(char *)(iVar5 + 8) == '\x06') {
          local_54 = local_54 + *(float *)(iVar2 + 0xc);
          local_50 = local_50 + *(float *)(iVar2 + 0x10);
          local_4c = local_4c + *(float *)(iVar2 + 0x14);
          (**(code **)(*DAT_803dca88 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack96,0x200001,0xffffffff,0);
        }
        else {
          (**(code **)(*DAT_803dca88 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack96,2,0xffffffff,0);
        }
      }
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  FUN_80286124();
  return;
}

