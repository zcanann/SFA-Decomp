// Function: FUN_801a6e70
// Entry: 801a6e70
// Size: 212 bytes

void FUN_801a6e70(short *param_1,int param_2)

{
  undefined uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  puVar2[1] = 1;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  *(code **)(param_1 + 0x5e) = FUN_801a6c28;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - DOUBLE_803e44e0) *
       FLOAT_803e44d4;
  if (*(float *)(param_1 + 4) == FLOAT_803e44d8) {
    *(float *)(param_1 + 4) = FLOAT_803e44d0;
  }
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  if (*(short *)(param_2 + 0x1a) == -1) {
    *puVar2 = 0;
  }
  else {
    uVar1 = FUN_8001ffb4();
    *puVar2 = uVar1;
  }
  return;
}

