// Function: FUN_801fa2f4
// Entry: 801fa2f4
// Size: 876 bytes

void FUN_801fa2f4(int param_1)

{
  short sVar1;
  int iVar2;
  float *pfVar3;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  longlong local_20;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  if (FLOAT_803e608c == *pfVar3) {
    FUN_800658a4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14),param_1,pfVar3,0);
    *pfVar3 = *(float *)(param_1 + 0x10) - *pfVar3;
  }
  if (FLOAT_803e6090 < *(float *)(param_1 + 0x28)) {
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) + FLOAT_803e6094;
  }
  *(float *)(param_1 + 0xc) =
       *(float *)(param_1 + 0x24) * FLOAT_803db414 + *(float *)(param_1 + 0xc);
  *(float *)(param_1 + 0x10) =
       *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
  *(float *)(param_1 + 0x14) =
       *(float *)(param_1 + 0x2c) * FLOAT_803db414 + *(float *)(param_1 + 0x14);
  local_2c = FLOAT_803e608c;
  local_28 = FLOAT_803e608c;
  local_24 = FLOAT_803e608c;
  local_30 = FLOAT_803e6088;
  local_34 = 0;
  local_36 = 0;
  local_38 = 0;
  iVar2 = FUN_800221a0(0,4);
  if (iVar2 == 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x38a,&local_38,0x80001,0xffffffff,0);
  }
  local_2c = (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80)) / FLOAT_803e6098;
  local_28 = (*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84)) / FLOAT_803e6098;
  local_24 = (*(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88)) / FLOAT_803e6098;
  iVar2 = FUN_800221a0(0,4);
  if (iVar2 == 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x38a,&local_38,0x80001,0xffffffff,0);
  }
  local_2c = local_2c * FLOAT_803e609c;
  local_28 = local_28 * FLOAT_803e609c;
  local_24 = local_24 * FLOAT_803e609c;
  iVar2 = FUN_800221a0(0,4);
  if (iVar2 == 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x38a,&local_38,0x80001,0xffffffff,0);
  }
  iVar2 = FUN_800221a0(0,2);
  if (iVar2 == 0) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x38b,&local_38,1,0xffffffff,0);
  }
  iVar2 = *(int *)(param_1 + 0x54);
  if (iVar2 == 0) {
LAB_801fa57c:
    if ((*pfVar3 <= *(float *)(param_1 + 0x10)) || (*(char *)((int)pfVar3 + 10) != '\0'))
    goto LAB_801fa5e8;
  }
  else {
    *(undefined *)(iVar2 + 0x6e) = 0xb;
    *(undefined *)(iVar2 + 0x6f) = 1;
    *(undefined4 *)(iVar2 + 0x48) = 0x10;
    *(undefined4 *)(iVar2 + 0x4c) = 0x10;
    if (*(int *)(iVar2 + 0x50) == 0) goto LAB_801fa57c;
  }
  *(undefined *)((int)pfVar3 + 10) = 1;
  iVar2 = 10;
  FUN_8000b7bc(param_1,0x7f);
  do {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x38e,&local_38,1,0xffffffff,0);
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
LAB_801fa5e8:
  if (*(char *)((int)pfVar3 + 10) != '\0') {
    local_20 = (longlong)(int)FLOAT_803db414;
    sVar1 = (ushort)*(byte *)(param_1 + 0x36) - (short)(int)FLOAT_803db414;
    if (sVar1 < 0) {
      sVar1 = 0;
    }
    *(char *)(param_1 + 0x36) = (char)sVar1;
  }
  if (*(float *)(param_1 + 0x10) < *pfVar3 - FLOAT_803e60a0) {
    FUN_8002cbc4(param_1);
  }
  return;
}

