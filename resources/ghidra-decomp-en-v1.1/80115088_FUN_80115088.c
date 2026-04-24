// Function: FUN_80115088
// Entry: 80115088
// Size: 376 bytes

void FUN_80115088(short *param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  uint *puVar3;
  ushort local_38;
  short local_36;
  short local_34;
  float local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  undefined4 uStack_20;
  float local_1c [4];
  
  if (*(char *)(param_2 + 0x601) != '\0') {
    puVar3 = FUN_80039598();
    FUN_8003ad0c((int)param_1,puVar3,(uint)*(byte *)(param_2 + 0x610));
    FUN_80038524(param_1,param_3,&local_30,&local_2c,&local_28,0);
    FUN_80038524(param_1,param_3 + 1,&local_24,&uStack_20,local_1c,0);
    fVar2 = FLOAT_803e294c;
    fVar1 = FLOAT_803e2948;
    *(float *)(param_2 + 4) = (FLOAT_803e2948 * local_30 + local_24) * FLOAT_803e294c;
    *(undefined4 *)(param_2 + 8) = local_2c;
    *(float *)(param_2 + 0xc) = (fVar1 * local_28 + local_1c[0]) * fVar2;
    *(float *)(param_2 + 4) = *(float *)(param_2 + 4) - *(float *)(param_1 + 6);
    *(float *)(param_2 + 8) = *(float *)(param_2 + 8) - *(float *)(param_1 + 8);
    *(float *)(param_2 + 0xc) = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 10);
    local_38 = -param_1[2];
    local_36 = -param_1[1];
    local_34 = -*param_1;
    FUN_80021b8c(&local_38,(float *)(param_2 + 4));
    *(undefined *)(param_2 + 0x601) = 0;
  }
  FUN_80038524(param_1,param_3,&local_30,&local_2c,&local_28,0);
  *(float *)(param_2 + 0x10) = local_30;
  *(undefined4 *)(param_2 + 0x14) = local_2c;
  *(float *)(param_2 + 0x18) = local_28;
  return;
}

