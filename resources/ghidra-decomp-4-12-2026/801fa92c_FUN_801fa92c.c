// Function: FUN_801fa92c
// Entry: 801fa92c
// Size: 876 bytes

void FUN_801fa92c(int param_1)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  float *pfVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  longlong local_20;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  if (FLOAT_803e6d24 == *pfVar4) {
    FUN_80065a20((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14),param_1,pfVar4,0);
    *pfVar4 = *(float *)(param_1 + 0x10) - *pfVar4;
  }
  if (FLOAT_803e6d28 < *(float *)(param_1 + 0x28)) {
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) + FLOAT_803e6d2c;
  }
  *(float *)(param_1 + 0xc) =
       *(float *)(param_1 + 0x24) * FLOAT_803dc074 + *(float *)(param_1 + 0xc);
  *(float *)(param_1 + 0x10) =
       *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
  *(float *)(param_1 + 0x14) =
       *(float *)(param_1 + 0x2c) * FLOAT_803dc074 + *(float *)(param_1 + 0x14);
  local_2c = FLOAT_803e6d24;
  local_28 = FLOAT_803e6d24;
  local_24 = FLOAT_803e6d24;
  local_30 = FLOAT_803e6d20;
  local_34 = 0;
  local_36 = 0;
  local_38 = 0;
  uVar2 = FUN_80022264(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x38a,&local_38,0x80001,0xffffffff,0);
  }
  dVar6 = (double)(*(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88));
  dVar5 = (double)FLOAT_803e6d30;
  local_2c = (float)((double)(*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80)) / dVar5);
  local_28 = (float)((double)(*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84)) / dVar5);
  local_24 = (float)(dVar6 / dVar5);
  uVar2 = FUN_80022264(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x38a,&local_38,0x80001,0xffffffff,0);
  }
  local_2c = local_2c * FLOAT_803e6d34;
  local_28 = local_28 * FLOAT_803e6d34;
  local_24 = local_24 * FLOAT_803e6d34;
  uVar2 = FUN_80022264(0,4);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x38a,&local_38,0x80001,0xffffffff,0);
  }
  uVar2 = FUN_80022264(0,2);
  if (uVar2 == 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x38b,&local_38,1,0xffffffff,0);
  }
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 == 0) {
LAB_801fabb4:
    if ((*pfVar4 <= *(float *)(param_1 + 0x10)) || (*(char *)((int)pfVar4 + 10) != '\0'))
    goto LAB_801fac20;
  }
  else {
    *(undefined *)(iVar3 + 0x6e) = 0xb;
    *(undefined *)(iVar3 + 0x6f) = 1;
    *(undefined4 *)(iVar3 + 0x48) = 0x10;
    *(undefined4 *)(iVar3 + 0x4c) = 0x10;
    if (*(int *)(iVar3 + 0x50) == 0) goto LAB_801fabb4;
  }
  *(undefined *)((int)pfVar4 + 10) = 1;
  iVar3 = 10;
  FUN_8000b7dc(param_1,0x7f);
  do {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x38e,&local_38,1,0xffffffff,0);
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
LAB_801fac20:
  if (*(char *)((int)pfVar4 + 10) != '\0') {
    local_20 = (longlong)(int)FLOAT_803dc074;
    sVar1 = (ushort)*(byte *)(param_1 + 0x36) - (short)(int)FLOAT_803dc074;
    if (sVar1 < 0) {
      sVar1 = 0;
    }
    *(char *)(param_1 + 0x36) = (char)sVar1;
  }
  if ((double)*(float *)(param_1 + 0x10) < (double)(float)((double)*pfVar4 - (double)FLOAT_803e6d38)
     ) {
    FUN_8002cc9c((double)*pfVar4,(double)*(float *)(param_1 + 0x10),dVar6,in_f4,in_f5,in_f6,in_f7,
                 in_f8,param_1);
  }
  return;
}

