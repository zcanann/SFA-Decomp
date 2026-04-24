// Function: FUN_80201990
// Entry: 80201990
// Size: 660 bytes

void FUN_80201990(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  ushort *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 uVar6;
  undefined4 uVar7;
  short *psVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  undefined4 local_58;
  undefined4 local_54;
  int local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  uVar11 = FUN_80286840();
  fVar1 = FLOAT_803e6f40;
  puVar2 = (ushort *)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  iVar9 = *(int *)(*(int *)(puVar2 + 0x5c) + 0x40c);
  uVar7 = *(undefined4 *)(iVar9 + 0x30);
  uVar6 = *(undefined4 *)(iVar9 + 0x2c);
  *(float *)(iVar5 + 0x280) = FLOAT_803e6f40;
  *(float *)(iVar5 + 0x284) = fVar1;
  *(byte *)(iVar9 + 0x14) = *(byte *)(iVar9 + 0x14) | 2;
  if ((*(int *)(iVar9 + 0x18) == 0) && (*(short *)(iVar9 + 0x1c) != -1)) {
    local_38 = *(undefined4 *)(iVar9 + 0x30);
    local_3c = *(undefined4 *)(iVar9 + 0x2c);
    psVar8 = *(short **)(iVar9 + 0x24);
    local_40 = *(undefined4 *)(iVar9 + 0x28);
    uVar3 = FUN_800138e4(psVar8);
    if (uVar3 == 0) {
      FUN_80013978(psVar8,(uint)&local_40);
    }
    psVar8 = *(short **)(iVar9 + 0x24);
    local_4c = 8;
    local_48 = uVar6;
    local_44 = uVar7;
    uVar3 = FUN_800138e4(psVar8);
    if (uVar3 == 0) {
      FUN_80013978(psVar8,(uint)&local_4c);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
    local_50 = (int)*(short *)(iVar9 + 0x1c);
    psVar8 = *(short **)(iVar9 + 0x24);
    local_58 = 9;
    local_54 = 0;
    uVar3 = FUN_800138e4(psVar8);
    if (uVar3 == 0) {
      FUN_80013978(psVar8,(uint)&local_58);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  else {
    *(byte *)(iVar9 + 0x15) = *(byte *)(iVar9 + 0x15) | 4;
    if ((*(int *)(iVar9 + 0x18) != 0) && ((*(uint *)(iVar5 + 0x314) & 0x200) != 0)) {
      iVar4 = *(int *)(iVar5 + 0x2d0);
      local_34 = *(float *)(iVar4 + 0xc) - *(float *)(puVar2 + 6);
      local_30 = *(float *)(iVar4 + 0x10) - *(float *)(puVar2 + 8);
      local_2c = *(float *)(iVar4 + 0x14) - *(float *)(puVar2 + 10);
      dVar10 = FUN_80293900((double)(local_34 * local_34 + local_2c * local_2c));
      local_30 = local_30 * FLOAT_803e6fa8;
      param_2 = (double)local_30;
      dVar10 = (double)(float)(dVar10 / (double)FLOAT_803e6fac);
      dVar10 = (double)(float)(-(double)(float)(dVar10 * (double)(float)((double)FLOAT_803e6fb0 *
                                                                        dVar10) - param_2) / dVar10)
      ;
      local_24 = (float)(dVar10 * (double)FLOAT_803e6fb4);
      local_28 = FLOAT_803e6f40;
      local_20 = FLOAT_803e6fb8;
      in_r6 = 0x11;
      FUN_800379bc(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar9 + 0x18),0x11,(uint)puVar2,0x11,in_r7,in_r8,in_r9,in_r10);
      (**(code **)(**(int **)(*(int *)(iVar9 + 0x18) + 0x68) + 0x24))
                (*(int *)(iVar9 + 0x18),&local_28);
      *(undefined4 *)(iVar9 + 0x18) = 0;
      *(undefined2 *)(iVar9 + 0x1c) = 0xffff;
    }
    iVar4 = FUN_800386e0(puVar2,*(int *)(iVar5 + 0x2d0),(float *)0x0);
    *puVar2 = *puVar2 + (short)iVar4;
    *(undefined *)(iVar5 + 0x34d) = 0x11;
    if (*(char *)(iVar5 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar2,0x12,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(undefined *)(iVar5 + 0x346) = 0;
    }
    if (*(char *)(iVar5 + 0x346) != '\0') {
      *(undefined *)(iVar9 + 0x34) = 1;
    }
  }
  FUN_8028688c();
  return;
}

