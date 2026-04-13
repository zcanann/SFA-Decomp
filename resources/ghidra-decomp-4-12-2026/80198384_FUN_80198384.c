// Function: FUN_80198384
// Entry: 80198384
// Size: 744 bytes

/* WARNING: Removing unreachable block (ram,0x80198644) */
/* WARNING: Removing unreachable block (ram,0x80198394) */

void FUN_80198384(uint param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  short sVar7;
  int iVar6;
  int iVar8;
  undefined4 *puVar9;
  double dVar10;
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
  
  puVar9 = *(undefined4 **)(param_1 + 0xb8);
  iVar8 = *(int *)(param_1 + 0x4c);
  iVar4 = FUN_8002bac4();
  if (iVar4 != 0) {
    if ((int)*(short *)(iVar8 + 0x18) == 0xffffffff) {
      sVar7 = 1;
    }
    else {
      uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x18));
      sVar7 = (short)uVar5;
    }
    if (sVar7 != 0) {
      if ((*(byte *)(iVar8 + 0x23) & 0x10) == 0) {
        FUN_8000da78(param_1,(ushort)*puVar9);
        FUN_8000da78(param_1,(ushort)puVar9[1]);
      }
      iVar6 = *(int *)(param_1 + 0xf4);
      if (0 < iVar6) {
        if (0 < iVar6) {
          *(uint *)(param_1 + 0xf4) = iVar6 - (uint)DAT_803dc070;
        }
      }
      else {
        fVar1 = *(float *)(param_1 + 0x18) - *(float *)(iVar4 + 0x18);
        fVar2 = *(float *)(param_1 + 0x1c) - *(float *)(iVar4 + 0x1c);
        fVar3 = *(float *)(param_1 + 0x20) - *(float *)(iVar4 + 0x20);
        dVar10 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        uStack_3c = (uint)*(byte *)(iVar8 + 0x20) << 4 ^ 0x80000000;
        local_40 = 0x43300000;
        if (((dVar10 <= (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4d48))
            || (*(byte *)(iVar8 + 0x20) == 0)) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
          dVar10 = DOUBLE_803e4d48;
          for (sVar7 = 0; sVar7 < (short)(ushort)*(byte *)(iVar8 + 0x24); sVar7 = sVar7 + 1) {
            uStack_3c = FUN_80022264(-(uint)*(byte *)(iVar8 + 0x1d),(uint)*(byte *)(iVar8 + 0x1d));
            uStack_3c = uStack_3c ^ 0x80000000;
            local_40 = 0x43300000;
            local_4c = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar10);
            uStack_34 = FUN_80022264(-(uint)*(byte *)(iVar8 + 0x1f),(uint)*(byte *)(iVar8 + 0x1f));
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_48 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar10);
            uStack_2c = FUN_80022264(-(uint)*(byte *)(iVar8 + 0x1e),(uint)*(byte *)(iVar8 + 0x1e));
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_44 = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar10);
            if ((*(byte *)(iVar8 + 0x23) & 1) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,800,auStack_58,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar8 + 0x23) & 2) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x321,auStack_58,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar8 + 0x23) & 4) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x322,auStack_58,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar8 + 0x23) & 8) != 0) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x351,auStack_58,4,0xffffffff,0);
            }
          }
        }
        *(uint *)(param_1 + 0xf4) = -(uint)*(byte *)(iVar8 + 0x24);
      }
    }
  }
  return;
}

