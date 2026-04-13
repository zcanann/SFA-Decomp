// Function: FUN_8018f854
// Entry: 8018f854
// Size: 2220 bytes

/* WARNING: Removing unreachable block (ram,0x801900e0) */
/* WARNING: Removing unreachable block (ram,0x8018f864) */

void FUN_8018f854(void)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  short sVar4;
  int iVar5;
  double in_f31;
  double dVar6;
  double in_ps31_1;
  ushort local_68;
  undefined2 local_66;
  short local_64;
  undefined auStack_60 [8];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_8028683c();
  iVar5 = *(int *)(iVar2 + 0xb8);
  local_58 = FLOAT_803e4b00;
  bVar1 = *(byte *)(iVar5 + 8);
  if (bVar1 == 0) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4af8);
      uStack_3c = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4af8);
      uStack_44 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4af8);
      local_68 = *(ushort *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80021b8c(&local_68,&local_54);
      local_54 = local_54 + *(float *)(iVar2 + 0xc);
      local_50 = local_50 + *(float *)(iVar2 + 0x10);
      local_4c = local_4c + *(float *)(iVar2 + 0x14);
      (**(code **)(*DAT_803dd708 + 8))
                (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_44 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        uStack_3c = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_34 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        local_68 = *(ushort *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80021b8c(&local_68,&local_54);
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
      }
    }
  }
  else if (bVar1 == 1) {
    piVar3 = (int *)FUN_80013ee8(*(ushort *)(iVar5 + 10) + 0x58 & 0xffff);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,0);
      }
    }
    FUN_80013e4c((undefined *)piVar3);
  }
  else if (bVar1 == 2) {
    piVar3 = (int *)FUN_80013ee8(*(ushort *)(iVar5 + 10) + 0xab & 0xffff);
    if (*(short *)(iVar5 + 0xc) < 1) {
      (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
    }
    else {
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        (**(code **)(*piVar3 + 4))(iVar2,0,0,1,0xffffffff,*(ushort *)(iVar5 + 10) & 0xff,0);
      }
    }
    FUN_80013e4c((undefined *)piVar3);
  }
  else if (bVar1 == 3) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4af8);
      uStack_3c = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4af8);
      uStack_44 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4af8);
      local_68 = *(ushort *)(iVar5 + 0x1a);
      local_66 = *(undefined2 *)(iVar5 + 0x1c);
      local_64 = *(short *)(iVar5 + 0x1e);
      if (*(int *)(iVar2 + 0x30) != 0) {
        local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
      }
      FUN_80021b8c(&local_68,&local_54);
      (**(code **)(*DAT_803dd708 + 8))(iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_34 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        uStack_3c = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_44 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        local_68 = *(ushort *)(iVar5 + 0x1a);
        local_66 = *(undefined2 *)(iVar5 + 0x1c);
        local_64 = *(short *)(iVar5 + 0x1e);
        if (*(int *)(iVar2 + 0x30) != 0) {
          local_64 = local_64 + *(short *)(*(int *)(iVar2 + 0x30) + 4);
        }
        FUN_80021b8c(&local_68,&local_54);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
      }
    }
  }
  else if (5 < bVar1) {
    if (*(short *)(iVar5 + 0xc) < 1) {
      uStack_34 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4af8);
      uStack_3c = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4af8);
      uStack_44 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4af8);
      FUN_80021b8c((ushort *)(iVar5 + 0x1a),&local_54);
      if (*(char *)(iVar5 + 8) == '\x06') {
        local_54 = local_54 + *(float *)(iVar2 + 0xc);
        local_50 = local_50 + *(float *)(iVar2 + 0x10);
        local_4c = local_4c + *(float *)(iVar2 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
      }
    }
    else {
      dVar6 = DOUBLE_803e4af8;
      for (sVar4 = 0; sVar4 < *(short *)(iVar5 + 0xc); sVar4 = sVar4 + 1) {
        uStack_34 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x14),(uint)*(ushort *)(iVar5 + 0x14));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_54 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar6);
        uStack_3c = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x18),(uint)*(ushort *)(iVar5 + 0x18));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_50 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar6);
        uStack_44 = FUN_80022264(-(uint)*(ushort *)(iVar5 + 0x16),(uint)*(ushort *)(iVar5 + 0x16));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_4c = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar6);
        FUN_80021b8c((ushort *)(iVar5 + 0x1a),&local_54);
        if (*(char *)(iVar5 + 8) == '\x06') {
          local_54 = local_54 + *(float *)(iVar2 + 0xc);
          local_50 = local_50 + *(float *)(iVar2 + 0x10);
          local_4c = local_4c + *(float *)(iVar2 + 0x14);
          (**(code **)(*DAT_803dd708 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,0x200001,0xffffffff,0);
        }
        else {
          (**(code **)(*DAT_803dd708 + 8))
                    (iVar2,*(undefined2 *)(iVar5 + 10),auStack_60,2,0xffffffff,0);
        }
      }
    }
  }
  FUN_80286888();
  return;
}

