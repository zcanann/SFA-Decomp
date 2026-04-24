// Function: FUN_801ee0c0
// Entry: 801ee0c0
// Size: 392 bytes

void FUN_801ee0c0(undefined2 *param_1)

{
  char cVar3;
  int iVar1;
  undefined2 *puVar2;
  float local_38;
  float local_34;
  float local_30;
  undefined2 local_2c;
  undefined2 local_2a;
  undefined2 local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  cVar3 = FUN_8002e04c();
  if (cVar3 != '\0') {
    FUN_8000bb18(0,0x127);
    local_20 = FLOAT_803e5c70;
    local_1c = FLOAT_803e5c70;
    local_18 = FLOAT_803e5c70;
    local_24 = FLOAT_803e5c74;
    local_2c = *param_1;
    local_2a = param_1[1];
    local_28 = param_1[2];
    local_38 = FLOAT_803e5c70;
    local_34 = FLOAT_803e5c78;
    local_30 = FLOAT_803e5c7c;
    FUN_80021ac8(&local_2c,&local_38);
    iVar1 = FUN_8002bdf4(0x18,0x119);
    *(undefined *)(iVar1 + 6) = 0xff;
    *(undefined *)(iVar1 + 7) = 0xff;
    *(undefined *)(iVar1 + 4) = 2;
    *(undefined *)(iVar1 + 5) = 1;
    FUN_8003842c(param_1,4,iVar1 + 8,iVar1 + 0xc,iVar1 + 0x10,0);
    puVar2 = (undefined2 *)FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (puVar2 != (undefined2 *)0x0) {
      local_20 = FLOAT_803e5c70;
      local_1c = FLOAT_803e5c70;
      local_18 = FLOAT_803e5c70;
      local_24 = FLOAT_803e5c74;
      local_2c = *param_1;
      local_2a = param_1[1];
      local_28 = 0;
      local_38 = FLOAT_803e5c70;
      local_34 = FLOAT_803e5c70;
      local_30 = FLOAT_803e5c80;
      FUN_80021ac8(&local_2c,&local_38);
      *(float *)(puVar2 + 0x12) = local_38;
      *(float *)(puVar2 + 0x14) = local_34;
      *(float *)(puVar2 + 0x16) = local_30;
      *(undefined4 *)(puVar2 + 0x7a) = 0x5a;
      *(undefined2 **)(puVar2 + 0x7c) = param_1;
      puVar2[2] = 0;
      puVar2[1] = 0;
      *puVar2 = 0;
    }
  }
  return;
}

