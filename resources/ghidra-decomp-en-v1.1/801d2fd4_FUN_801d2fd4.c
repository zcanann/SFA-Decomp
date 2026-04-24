// Function: FUN_801d2fd4
// Entry: 801d2fd4
// Size: 336 bytes

void FUN_801d2fd4(ushort *param_1)

{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_78;
  float local_74;
  float local_70;
  ushort local_6c;
  ushort local_6a;
  ushort local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float afStack_54 [18];
  
  iVar4 = *(int *)(param_1 + 0x26);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_8002becc(0x24,0x198);
    local_6c = *param_1;
    local_6a = param_1[1];
    local_68 = param_1[2];
    local_60 = FLOAT_803e6004;
    local_5c = FLOAT_803e6004;
    local_58 = FLOAT_803e6004;
    local_64 = FLOAT_803e6008;
    FUN_80021fac(afStack_54,&local_6c);
    dVar5 = (double)FLOAT_803e6004;
    FUN_80022790(dVar5,(double)FLOAT_803e6008,dVar5,afStack_54,&local_78,&local_74,&local_70);
    dVar6 = (double)FLOAT_803e600c;
    local_60 = (float)(dVar6 * (double)local_78);
    local_5c = (float)(dVar6 * (double)local_74);
    local_58 = (float)(dVar6 * (double)local_70);
    *(float *)(puVar3 + 4) = *(float *)(param_1 + 6) + local_60;
    *(float *)(puVar3 + 6) = *(float *)(param_1 + 8) + local_5c;
    fVar1 = *(float *)(param_1 + 10);
    *(float *)(puVar3 + 8) = (float)((double)fVar1 + (double)local_58);
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 2) = 2;
    puVar3[0xd] = (short)((int)*(char *)(iVar4 + 0x1e) << 8);
    puVar3[0xe] = *param_1;
    FUN_8002e088((double)fVar1,dVar6,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,puVar3,5,0xff,0xffffffff,
                 (uint *)0x0,in_r8,in_r9,in_r10);
  }
  return;
}

