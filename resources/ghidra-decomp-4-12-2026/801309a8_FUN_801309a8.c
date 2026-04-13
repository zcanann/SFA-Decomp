// Function: FUN_801309a8
// Entry: 801309a8
// Size: 184 bytes

void FUN_801309a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  undefined *puVar2;
  undefined *extraout_r4;
  int iVar3;
  undefined2 *puVar4;
  
  puVar2 = &DAT_803b0000;
  puVar4 = &DAT_803aa0b8;
  for (iVar3 = 0; iVar3 < DAT_803de591; iVar3 = iVar3 + 1) {
    puVar4[0xb] = *(undefined2 *)(param_9 + 0x16);
    *(undefined *)(puVar4 + 0xd) = *(undefined *)(param_9 + 0x1a);
    puVar4[2] = *(undefined2 *)(param_9 + 4);
    if (*(int *)(param_9 + 0x10) == -1) {
      if (*(int *)(puVar4 + 8) != 0) {
        param_1 = FUN_80054484();
        puVar2 = extraout_r4;
      }
      *(undefined4 *)(puVar4 + 8) = 0;
    }
    else if (*(int *)(puVar4 + 8) == 0) {
      uVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(param_9 + 0x10),puVar2,param_11,param_12,param_13,param_14,
                           param_15,param_16);
      *(undefined4 *)(puVar4 + 8) = uVar1;
    }
    puVar4 = puVar4 + 0x1e;
    param_9 = param_9 + 0x3c;
  }
  return;
}

