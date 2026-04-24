// Function: FUN_80171ed0
// Entry: 80171ed0
// Size: 384 bytes

void FUN_80171ed0(ushort *param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  ushort local_78;
  ushort local_76;
  ushort local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float afStack_60 [16];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  uStack_1c = *(byte *)(param_2 + 0x2a) ^ 0x80000000;
  local_20 = 0x43300000;
  local_18 = 0x43300000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e40d0);
  if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e40d0) < FLOAT_803e40bc) {
    fVar1 = FLOAT_803e40bc;
  }
  *(float *)(param_1 + 4) = fVar1 * FLOAT_803e40c0;
  *param_1 = (ushort)((int)(short)(ushort)*(byte *)(param_2 + 0x29) << 8);
  local_78 = *param_1;
  local_76 = param_1[1];
  local_74 = param_1[2];
  local_70 = FLOAT_803e40b8;
  local_6c = FLOAT_803e40c4;
  local_68 = FLOAT_803e40c4;
  local_64 = FLOAT_803e40c4;
  uStack_14 = uStack_1c;
  FUN_80021fac(afStack_60,&local_78);
  FUN_80022790((double)FLOAT_803e40c4,(double)FLOAT_803e40c4,(double)FLOAT_803e40b8,afStack_60,
               (float *)(iVar4 + 0x10),(float *)(iVar4 + 0x14),(float *)(iVar4 + 0x18));
  *(float *)(iVar4 + 0x1c) =
       -(*(float *)(param_1 + 10) * *(float *)(iVar4 + 0x18) +
        *(float *)(param_1 + 6) * *(float *)(iVar4 + 0x10) +
        *(float *)(param_1 + 8) * *(float *)(iVar4 + 0x14));
  *(float *)(iVar4 + 0x20) = FLOAT_803e40c8 * *(float *)(param_1 + 4);
  iVar3 = 0;
  do {
    uVar2 = FUN_80022264(0,0xf0);
    *(short *)(iVar4 + 0x34) = (short)uVar2;
    iVar4 = iVar4 + 2;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  *(int *)(param_1 + 0x7a) = (int)*(char *)(param_2 + 0x28);
  param_1[0x58] = param_1[0x58] | 0xa000;
  return;
}

