// Function: FUN_8021e864
// Entry: 8021e864
// Size: 168 bytes

void FUN_8021e864(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined2 *puVar1;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined auStack80 [68];
  
  puVar1 = (undefined2 *)FUN_8002b9ec();
  local_5c = *(undefined4 *)(puVar1 + 6);
  local_58 = *(undefined4 *)(puVar1 + 8);
  local_54 = *(undefined4 *)(puVar1 + 10);
  local_68 = *puVar1;
  local_66 = puVar1[1];
  local_64 = puVar1[2];
  local_60 = FLOAT_803e6ab8;
  FUN_80021ee8(auStack80,&local_68);
  FUN_800226cc((double)FLOAT_803e6aa8,(double)FLOAT_803e6b38,(double)FLOAT_803e6b3c,auStack80,
               param_2,param_3,param_4);
  return;
}

