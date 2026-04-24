// Function: FUN_80165188
// Entry: 80165188
// Size: 592 bytes

undefined4 FUN_80165188(int param_1,uint *param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  *(undefined *)((int)param_2 + 0x34d) = 3;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    FUN_80035f00();
    *(float *)(param_1 + 0x24) = -*(float *)(param_1 + 0x24);
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) + FLOAT_803e2fd8;
    *(float *)(param_1 + 0x2c) = -*(float *)(param_1 + 0x2c);
    FUN_80030334((double)FLOAT_803e2fdc,param_1,3,0);
    *(float *)(iVar2 + 0x44) = FLOAT_803e2fe0;
  }
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6d) = 0;
  *param_2 = *param_2 | 0x4000;
  fVar1 = FLOAT_803e2fe4;
  *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e2fe4;
  *(float *)(param_1 + 0x28) = FLOAT_803e2fe8 * (*(float *)(param_1 + 0x28) - FLOAT_803e2fec);
  *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  FUN_8002b95c((double)*(float *)(param_1 + 0x24),(double)*(float *)(param_1 + 0x28),
               (double)*(float *)(param_1 + 0x2c),param_1);
  if (*(float *)(param_1 + 0xc) < *(float *)(iVar2 + 0x48)) {
    *(float *)(param_1 + 0xc) = *(float *)(iVar2 + 0x48);
    *(float *)(param_1 + 0x24) = FLOAT_803e2ff0 * -*(float *)(param_1 + 0x24);
  }
  if (*(float *)(iVar2 + 0x4c) < *(float *)(param_1 + 0xc)) {
    *(float *)(param_1 + 0xc) = *(float *)(iVar2 + 0x4c);
    *(float *)(param_1 + 0x24) = FLOAT_803e2ff0 * -*(float *)(param_1 + 0x24);
  }
  if (*(float *)(param_1 + 0x10) < *(float *)(iVar2 + 0x5c)) {
    *(float *)(param_1 + 0x10) = *(float *)(iVar2 + 0x5c);
    *(float *)(param_1 + 0x28) = FLOAT_803e2ff0 * -*(float *)(param_1 + 0x28);
  }
  if (*(float *)(iVar2 + 0x58) < *(float *)(param_1 + 0x10)) {
    *(float *)(param_1 + 0x10) = *(float *)(iVar2 + 0x58);
    *(float *)(param_1 + 0x28) = FLOAT_803e2ff0 * -*(float *)(param_1 + 0x28);
  }
  if (*(float *)(param_1 + 0x14) < *(float *)(iVar2 + 0x54)) {
    *(float *)(param_1 + 0x14) = *(float *)(iVar2 + 0x54);
    *(float *)(param_1 + 0x2c) = FLOAT_803e2ff0 * -*(float *)(param_1 + 0x2c);
  }
  if (*(float *)(iVar2 + 0x50) < *(float *)(param_1 + 0x14)) {
    *(float *)(param_1 + 0x14) = *(float *)(iVar2 + 0x50);
    *(float *)(param_1 + 0x2c) = FLOAT_803e2ff0 * -*(float *)(param_1 + 0x2c);
  }
  if (FLOAT_803e2ff4 == *(float *)(param_1 + 0x98)) {
    FUN_800376d8(0,3,param_1,0xe0000,param_1);
    FUN_8002cbc4(param_1);
  }
  else {
    *(char *)(param_1 + 0x36) = -1 - (char)(int)(FLOAT_803e2ff8 * *(float *)(param_1 + 0x98));
  }
  return 0;
}

