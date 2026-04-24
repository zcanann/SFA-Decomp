// Function: FUN_801a3674
// Entry: 801a3674
// Size: 1188 bytes

/* WARNING: Removing unreachable block (ram,0x801a3af0) */
/* WARNING: Removing unreachable block (ram,0x801a3684) */

void FUN_801a3674(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined8 local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  FUN_80021b8c((ushort *)(param_3 + 0x1a),(float *)(param_2 + 0x10));
  *(float *)(param_2 + 0x4c) =
       *(float *)(param_2 + 0x10) * *(float *)(param_1 + 8) + *(float *)(param_3 + 8);
  *(float *)(param_2 + 0x50) =
       *(float *)(param_2 + 0x14) * *(float *)(param_1 + 8) + *(float *)(param_3 + 0xc);
  *(float *)(param_2 + 0x54) =
       *(float *)(param_2 + 0x18) * *(float *)(param_1 + 8) + *(float *)(param_3 + 0x10);
  *(undefined2 *)(param_2 + 0x68) = *(undefined2 *)(param_3 + 0x1a);
  *(undefined2 *)(param_2 + 0x66) = *(undefined2 *)(param_3 + 0x1c);
  *(undefined2 *)(param_2 + 100) = *(undefined2 *)(param_3 + 0x1e);
  uStack_44 = (int)*(short *)(param_3 + 0x20) ^ 0x80000000;
  local_48 = 0x43300000;
  local_50[0] = *(float *)(param_2 + 0x10) -
                (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5020);
  uStack_3c = (int)*(short *)(param_3 + 0x22) ^ 0x80000000;
  local_40 = 0x43300000;
  local_54 = *(float *)(param_2 + 0x14) -
             (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e5020);
  local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x24) ^ 0x80000000);
  local_58 = *(float *)(param_2 + 0x18) - (float)(local_38 - DOUBLE_803e5020);
  dVar4 = FUN_80293900((double)(local_58 * local_58 +
                               local_50[0] * local_50[0] + local_54 * local_54));
  dVar5 = (double)FLOAT_803e5000;
  if (dVar4 != dVar5) {
    local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2c) ^ 0x80000000);
    dVar4 = (double)((float)(local_38 - DOUBLE_803e5020) / (float)((double)FLOAT_803e5008 * dVar4));
    if ((((double)local_50[0] != dVar5) || ((double)local_54 != dVar5)) ||
       ((double)local_58 != dVar5)) {
      FUN_80070320(local_50,&local_54,&local_58);
    }
    *(float *)(param_2 + 0x40) = (float)((double)local_50[0] * dVar4);
    *(float *)(param_2 + 0x44) = (float)((double)local_54 * dVar4);
    *(float *)(param_2 + 0x48) = (float)((double)local_58 * dVar4);
    uVar3 = (uint)(FLOAT_803e500c * (float)((double)FLOAT_803e5010 + dVar4));
    local_38 = (double)(longlong)(int)uVar3;
    uStack_3c = FUN_80022264(0,uVar3);
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(param_2 + 0x1c) =
         (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e5020) / FLOAT_803e5014;
    uStack_44 = FUN_80022264(0,uVar3);
    uStack_44 = uStack_44 ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(param_2 + 0x20) =
         (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5020) / FLOAT_803e5014;
    uStack_2c = FUN_80022264(0,uVar3);
    dVar4 = DOUBLE_803e5020;
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(param_2 + 0x24) =
         (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5020) / FLOAT_803e5014;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x30) ^ 0x80000000);
    dVar4 = (double)((float)(local_28 - dVar4) / FLOAT_803e4ff0);
    if (FLOAT_803e5000 < *(float *)(param_1 + 0x24)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 1;
    }
    if (FLOAT_803e5000 < *(float *)(param_1 + 0x2c)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 2;
    }
    if (FLOAT_803e5000 < *(float *)(param_2 + 0x1c)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 4;
    }
    if (FLOAT_803e5000 < *(float *)(param_2 + 0x20)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 8;
    }
    if (FLOAT_803e5000 < *(float *)(param_2 + 0x24)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 0x10;
    }
    uVar3 = (uint)(FLOAT_803e500c * (float)((double)FLOAT_803e5010 + dVar4));
    local_28 = (double)(longlong)(int)uVar3;
    uStack_2c = FUN_80022264(0,uVar3);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(param_2 + 0x28) =
         (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5020) / FLOAT_803e500c;
    uVar2 = FUN_80022264(0,uVar3);
    local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(param_2 + 0x2c) = (float)(local_38 - DOUBLE_803e5020) / FLOAT_803e500c;
    uStack_3c = FUN_80022264(0,uVar3);
    dVar5 = DOUBLE_803e5020;
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(param_2 + 0x30) =
         (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e5020) / FLOAT_803e500c;
    *(float *)(param_2 + 0x34) = (float)((double)local_50[0] * dVar4);
    *(float *)(param_2 + 0x38) = (float)((double)local_54 * dVar4 - (double)FLOAT_803e5018);
    *(float *)(param_2 + 0x3c) = (float)((double)local_58 * dVar4);
    if ((int)*(short *)(param_3 + 0x2e) != 0) {
      local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2e) ^ 0x80000000);
      *(float *)(param_2 + 0x58) = (float)(local_28 - dVar5);
    }
    *(uint *)(param_2 + 0x5c) = (uint)*(ushort *)(param_3 + 0x38);
    if (*(short *)(param_3 + 0x38) == 0) {
      *(undefined4 *)(param_2 + 0x60) = 0xffffffff;
    }
    else {
      uVar3 = FUN_80022264(0,100);
      iVar1 = (uint)*(ushort *)(param_3 + 0x38) * (uVar3 + 100);
      iVar1 = iVar1 / 200 + (iVar1 >> 0x1f);
      *(int *)(param_2 + 0x60) = iVar1 - (iVar1 >> 0x1f);
    }
  }
  return;
}

