// Function: FUN_801d1f68
// Entry: 801d1f68
// Size: 644 bytes

void FUN_801d1f68(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  local_38 = 0x19;
  iVar2 = FUN_8002bac4();
  *(undefined **)(param_9 + 0xbc) = &LAB_801d0e18;
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x4000;
  uVar3 = FUN_80020078((int)*(short *)(param_10 + 0x1a));
  if (uVar3 != 0) {
    *(undefined *)(iVar4 + 0x136) = 8;
    FUN_80035ff8(param_9);
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
  }
  *(uint *)(*(int *)(param_9 + 100) + 0x30) = *(uint *)(*(int *)(param_9 + 100) + 0x30) | 0x810;
  *(float *)(iVar4 + 0x110) = FLOAT_803e5f78;
  dVar5 = (double)FLOAT_803e5f7c;
  uStack_14 = (uint)*(byte *)(param_10 + 0x1c);
  local_18 = 0x43300000;
  *(float *)(iVar4 + 0x114) =
       (float)(dVar5 * (double)((float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5f58) /
                               FLOAT_803e5f80));
  FUN_8003042c((double)FLOAT_803e5f20,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               1,0,param_12,param_13,param_14,param_15,param_16);
  dVar5 = (double)FLOAT_803e5f40;
  FUN_8002fb40(dVar5,dVar5);
  *(undefined4 *)(iVar4 + 0x118) = local_34;
  if (*(float *)(iVar4 + 0x118) < FLOAT_803e5f20) {
    *(float *)(iVar4 + 0x118) = -*(float *)(iVar4 + 0x118);
  }
  *(float *)(iVar4 + 0x118) = *(float *)(iVar4 + 0x118) * *(float *)(iVar4 + 0x110);
  *(float *)(iVar4 + 0x118) = *(float *)(iVar4 + 0x118) + FLOAT_803e5f38;
  FUN_8003042c((double)FLOAT_803e5f20,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               4,0,param_12,param_13,param_14,param_15,param_16);
  FUN_8002fb40((double)FLOAT_803e5f40,(double)FLOAT_803e5f40);
  *(undefined4 *)(iVar4 + 0x11c) = local_2c;
  if (*(float *)(iVar4 + 0x11c) < FLOAT_803e5f20) {
    *(float *)(iVar4 + 0x11c) = -*(float *)(iVar4 + 0x11c);
  }
  *(float *)(iVar4 + 0x11c) = *(float *)(iVar4 + 0x11c) + FLOAT_803e5f38;
  FUN_80037a5c(param_9,1);
  if ((*(byte *)(param_10 + 0x18) < 6) && (3 < *(byte *)(param_10 + 0x18))) {
    *(byte *)(iVar4 + 0x137) = *(byte *)(iVar4 + 0x137) | 2;
    (**(code **)(*DAT_803dd71c + 0x8c))((double)FLOAT_803e5f84,iVar4,param_9,&local_38,0xffffffff);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar4 + 0x68);
    *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar4 + 0x70);
  }
  *(float *)(iVar4 + 0x120) = FLOAT_803e5f88;
  fVar1 = FLOAT_803e5f8c;
  if (iVar2 == 0) {
    *(float *)(iVar4 + 0x108) = FLOAT_803e5f8c;
    *(float *)(iVar4 + 0x10c) = fVar1;
  }
  else {
    dVar5 = (double)FUN_800217c8((float *)(iVar2 + 0x18),(float *)(param_9 + 0x18));
    *(float *)(iVar4 + 0x108) = (float)dVar5;
    *(float *)(iVar4 + 0x10c) = (float)dVar5;
  }
  FUN_800372f8(param_9,0x31);
  FUN_800372f8(param_9,0x47);
  if (*(short *)(param_9 + 0x46) == 0x658) {
    *(undefined2 *)(iVar4 + 0x134) = 0x66d;
  }
  else {
    *(undefined2 *)(iVar4 + 0x134) = 0xc1;
  }
  return;
}

