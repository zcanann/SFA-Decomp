// Function: FUN_801a5c70
// Entry: 801a5c70
// Size: 272 bytes

void FUN_801a5c70(undefined2 *param_1,int param_2,int param_3)

{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  puVar4[3] = (int)*(short *)(param_2 + 0x1a);
  puVar4[2] = 0;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000) -
                 DOUBLE_803e4438) * FLOAT_803e4448;
  uVar2 = countLeadingZeros(((uint)(byte)((fVar1 == FLOAT_803e4430) << 1) << 0x1c) >> 0x1d ^ 1);
  if (uVar2 >> 5 != 0) {
    fVar1 = FLOAT_803e4440;
  }
  *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * fVar1;
  puVar4[1] = 0;
  FUN_80035f00(param_1);
  *(byte *)(puVar4 + 4) = *(byte *)(puVar4 + 4) & 0x7f;
  if (param_3 == 0) {
    *(undefined *)(param_1 + 0x1b) = 0;
    uVar3 = FUN_8001cc9c(param_1,0xff,0,0x4d,0);
    *puVar4 = uVar3;
  }
  return;
}

