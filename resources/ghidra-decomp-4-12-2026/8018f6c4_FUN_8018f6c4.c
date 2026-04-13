// Function: FUN_8018f6c4
// Entry: 8018f6c4
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x8018f834) */
/* WARNING: Removing unreachable block (ram,0x8018f6d4) */

void FUN_8018f6c4(void)

{
  int iVar1;
  short sVar2;
  int iVar3;
  double in_f31;
  double dVar4;
  double in_ps31_1;
  undefined8 uVar5;
  undefined auStack_58 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar5 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if (0 < (int)uVar5) {
    dVar4 = DOUBLE_803e4af8;
    for (sVar2 = 0; (int)sVar2 < (int)uVar5; sVar2 = sVar2 + 1) {
      uStack_3c = FUN_80022264(-(uint)*(ushort *)(iVar3 + 0x14),(uint)*(ushort *)(iVar3 + 0x14));
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_4c = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4);
      uStack_34 = FUN_80022264(-(uint)*(ushort *)(iVar3 + 0x18),(uint)*(ushort *)(iVar3 + 0x18));
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_48 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar4);
      uStack_2c = FUN_80022264(-(uint)*(ushort *)(iVar3 + 0x16),(uint)*(ushort *)(iVar3 + 0x16));
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_44 = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar4);
      FUN_80021b8c((ushort *)(iVar3 + 0x1a),&local_4c);
      if ((*(char *)(iVar3 + 8) == '\x04') || (*(char *)(iVar3 + 8) == '\x06')) {
        local_4c = local_4c + *(float *)(iVar1 + 0xc);
        local_48 = local_48 + *(float *)(iVar1 + 0x10);
        local_44 = local_44 + *(float *)(iVar1 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar1,*(undefined2 *)(iVar3 + 10),auStack_58,0x200001,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))
                  (iVar1,*(undefined2 *)(iVar3 + 10),auStack_58,2,0xffffffff,0);
      }
    }
  }
  FUN_80286888();
  return;
}

