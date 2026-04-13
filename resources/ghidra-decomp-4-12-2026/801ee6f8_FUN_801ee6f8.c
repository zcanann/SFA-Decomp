// Function: FUN_801ee6f8
// Entry: 801ee6f8
// Size: 392 bytes

void FUN_801ee6f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar4;
  float local_38;
  float local_34;
  float local_30;
  ushort local_2c;
  ushort local_2a;
  ushort local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    FUN_8000bb38(0,0x127);
    local_20 = FLOAT_803e6908;
    local_1c = FLOAT_803e6908;
    local_18 = FLOAT_803e6908;
    local_24 = FLOAT_803e690c;
    local_2c = *param_9;
    local_2a = param_9[1];
    local_28 = param_9[2];
    local_38 = FLOAT_803e6908;
    local_34 = FLOAT_803e6910;
    local_30 = FLOAT_803e6914;
    FUN_80021b8c(&local_2c,&local_38);
    puVar2 = FUN_8002becc(0x18,0x119);
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)((int)puVar2 + 5) = 1;
    uVar3 = 0;
    uVar4 = FUN_80038524(param_9,4,(float *)(puVar2 + 4),(undefined4 *)(puVar2 + 6),
                         (float *)(puVar2 + 8),0);
    puVar2 = (undefined2 *)
             FUN_8002e088(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                          0xff,0xffffffff,(uint *)0x0,uVar3,in_r9,in_r10);
    if (puVar2 != (undefined2 *)0x0) {
      local_20 = FLOAT_803e6908;
      local_1c = FLOAT_803e6908;
      local_18 = FLOAT_803e6908;
      local_24 = FLOAT_803e690c;
      local_2c = *param_9;
      local_2a = param_9[1];
      local_28 = 0;
      local_38 = FLOAT_803e6908;
      local_34 = FLOAT_803e6908;
      local_30 = FLOAT_803e6918;
      FUN_80021b8c(&local_2c,&local_38);
      *(float *)(puVar2 + 0x12) = local_38;
      *(float *)(puVar2 + 0x14) = local_34;
      *(float *)(puVar2 + 0x16) = local_30;
      *(undefined4 *)(puVar2 + 0x7a) = 0x5a;
      *(ushort **)(puVar2 + 0x7c) = param_9;
      puVar2[2] = 0;
      puVar2[1] = 0;
      *puVar2 = 0;
    }
  }
  return;
}

