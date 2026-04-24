// Function: FUN_802bb020
// Entry: 802bb020
// Size: 164 bytes

void FUN_802bb020(undefined2 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined auStack80 [68];
  
  local_5c = *(undefined4 *)(param_1 + 6);
  local_58 = *(undefined4 *)(param_1 + 8);
  local_54 = *(undefined4 *)(param_1 + 10);
  local_68 = *param_1;
  local_66 = param_1[1];
  local_64 = param_1[2];
  local_60 = FLOAT_803e8258;
  FUN_80021ee8(auStack80,&local_68);
  FUN_800226cc((double)FLOAT_803e8234,(double)FLOAT_803e8298,(double)FLOAT_803e829c,auStack80,
               param_2,param_3,param_4);
  return;
}

