// Function: FUN_8003bc7c
// Entry: 8003bc7c
// Size: 356 bytes

undefined4 FUN_8003bc7c(float *param_1,float *param_2)

{
  float fVar1;
  undefined4 uVar2;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_2c = *param_1;
  local_28 = param_1[1];
  local_24 = param_1[2];
  local_38 = param_1[4];
  local_34 = param_1[5];
  local_30 = param_1[6];
  local_20 = param_1[8];
  local_1c = param_1[9];
  local_18 = param_1[10];
  if (((((local_2c == FLOAT_803df684) && (local_28 == FLOAT_803df684)) &&
       (local_24 == FLOAT_803df684)) ||
      (((local_38 == FLOAT_803df684 && (local_34 == FLOAT_803df684)) && (local_30 == FLOAT_803df684)
       ))) || (((local_20 == FLOAT_803df684 && (local_1c == FLOAT_803df684)) &&
               (local_18 == FLOAT_803df684)))) {
    uVar2 = 0;
  }
  else {
    FUN_80247ef8(&local_2c,&local_2c);
    FUN_80247ef8(&local_38,&local_38);
    FUN_80247ef8(&local_20,&local_20);
    *param_2 = local_2c;
    param_2[1] = local_28;
    param_2[2] = local_24;
    fVar1 = FLOAT_803df684;
    param_2[3] = FLOAT_803df684;
    param_2[4] = local_38;
    param_2[5] = local_34;
    param_2[6] = local_30;
    param_2[7] = fVar1;
    param_2[8] = local_20;
    param_2[9] = local_1c;
    param_2[10] = local_18;
    param_2[0xb] = fVar1;
    uVar2 = 1;
  }
  return uVar2;
}

