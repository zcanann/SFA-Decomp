// Function: FUN_80177e64
// Entry: 80177e64
// Size: 400 bytes

void FUN_80177e64(undefined2 *param_1)

{
  int iVar1;
  undefined4 uVar2;
  float *pfVar3;
  undefined2 *puVar4;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = FUN_8002b9ec();
  pfVar3 = *(float **)(param_1 + 0x5c);
  if ((iVar1 != 0) && (puVar4 = *(undefined2 **)(iVar1 + 200), puVar4 != (undefined2 *)0x0)) {
    param_1[2] = puVar4[2];
    param_1[1] = puVar4[1];
    *param_1 = *puVar4;
    if (*(char *)(*(int *)(param_1 + 0x26) + 0x19) == '\0') {
      uVar2 = 1;
    }
    else {
      uVar2 = 3;
    }
    FUN_80035df4(param_1,0x10,uVar2,0);
    *pfVar3 = *pfVar3 - FLOAT_803db414;
    local_1c = FLOAT_803e3604;
    if (*pfVar3 <= FLOAT_803e3604) {
      *pfVar3 = *pfVar3 + FLOAT_803e3608;
      *(float *)(param_1 + 0x12) = local_1c;
      *(float *)(param_1 + 0x16) = local_1c;
      *(float *)(param_1 + 0x14) = FLOAT_803e360c;
      local_18 = local_1c;
      local_14 = local_1c;
      local_20 = FLOAT_803e3600;
      local_24 = puVar4[2];
      local_26 = puVar4[1];
      local_28 = *puVar4;
      FUN_80021ac8(&local_28,param_1 + 0x12);
      FUN_8003842c(puVar4,0,param_1 + 6,param_1 + 8,param_1 + 10,0);
      FUN_80035f20(param_1);
    }
    *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
  }
  return;
}

