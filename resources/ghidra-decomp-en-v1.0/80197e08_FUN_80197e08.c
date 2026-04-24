// Function: FUN_80197e08
// Entry: 80197e08
// Size: 744 bytes

/* WARNING: Removing unreachable block (ram,0x801980c8) */

void FUN_80197e08(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short sVar6;
  int iVar5;
  int iVar7;
  uint *puVar8;
  undefined4 uVar9;
  double dVar10;
  undefined8 in_f31;
  undefined auStack88 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  puVar8 = *(uint **)(param_1 + 0xb8);
  iVar7 = *(int *)(param_1 + 0x4c);
  iVar4 = FUN_8002b9ec();
  if (iVar4 != 0) {
    if (*(short *)(iVar7 + 0x18) == -1) {
      sVar6 = 1;
    }
    else {
      sVar6 = FUN_8001ffb4();
    }
    if (sVar6 != 0) {
      if ((*(byte *)(iVar7 + 0x23) & 0x10) == 0) {
        FUN_8000da58(param_1,*puVar8 & 0xffff);
        FUN_8000da58(param_1,puVar8[1] & 0xffff);
      }
      iVar5 = *(int *)(param_1 + 0xf4);
      if (0 < iVar5) {
        if (0 < iVar5) {
          *(uint *)(param_1 + 0xf4) = iVar5 - (uint)DAT_803db410;
        }
      }
      else {
        fVar1 = *(float *)(param_1 + 0x18) - *(float *)(iVar4 + 0x18);
        fVar2 = *(float *)(param_1 + 0x1c) - *(float *)(iVar4 + 0x1c);
        fVar3 = *(float *)(param_1 + 0x20) - *(float *)(iVar4 + 0x20);
        dVar10 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        uStack60 = (uint)*(byte *)(iVar7 + 0x20) << 4 ^ 0x80000000;
        local_40 = 0x43300000;
        if (((dVar10 <= (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e40b0)) ||
            (*(byte *)(iVar7 + 0x20) == 0)) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
          dVar10 = DOUBLE_803e40b0;
          for (sVar6 = 0; sVar6 < (short)(ushort)*(byte *)(iVar7 + 0x24); sVar6 = sVar6 + 1) {
            uStack60 = FUN_800221a0(-(uint)*(byte *)(iVar7 + 0x1d));
            uStack60 = uStack60 ^ 0x80000000;
            local_40 = 0x43300000;
            local_4c = (float)((double)CONCAT44(0x43300000,uStack60) - dVar10);
            uStack52 = FUN_800221a0(-(uint)*(byte *)(iVar7 + 0x1f));
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_48 = (float)((double)CONCAT44(0x43300000,uStack52) - dVar10);
            uStack44 = FUN_800221a0(-(uint)*(byte *)(iVar7 + 0x1e));
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_44 = (float)((double)CONCAT44(0x43300000,uStack44) - dVar10);
            if ((*(byte *)(iVar7 + 0x23) & 1) != 0) {
              (**(code **)(*DAT_803dca88 + 8))(param_1,800,auStack88,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar7 + 0x23) & 2) != 0) {
              (**(code **)(*DAT_803dca88 + 8))(param_1,0x321,auStack88,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar7 + 0x23) & 4) != 0) {
              (**(code **)(*DAT_803dca88 + 8))(param_1,0x322,auStack88,4,0xffffffff,0);
            }
            if ((*(byte *)(iVar7 + 0x23) & 8) != 0) {
              (**(code **)(*DAT_803dca88 + 8))(param_1,0x351,auStack88,4,0xffffffff,0);
            }
          }
        }
        *(uint *)(param_1 + 0xf4) = -(uint)*(byte *)(iVar7 + 0x24);
      }
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  return;
}

