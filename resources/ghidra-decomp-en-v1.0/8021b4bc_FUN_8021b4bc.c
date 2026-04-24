// Function: FUN_8021b4bc
// Entry: 8021b4bc
// Size: 192 bytes

void FUN_8021b4bc(undefined2 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined2 *puVar1;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined auStack80 [64];
  
  puVar1 = (undefined2 *)FUN_8002b9ec();
  if (puVar1 == (undefined2 *)0x0) {
    puVar1 = param_1;
  }
  local_5c = *(undefined4 *)(puVar1 + 6);
  local_58 = *(undefined4 *)(puVar1 + 8);
  local_54 = *(undefined4 *)(puVar1 + 10);
  local_68 = *puVar1;
  local_66 = puVar1[1];
  local_64 = puVar1[2];
  local_60 = FLOAT_803e6a48;
  FUN_80021ee8(auStack80,&local_68);
  FUN_800226cc((double)FLOAT_803e6a3c,(double)FLOAT_803dc300,(double)FLOAT_803dc304,auStack80,
               param_2,param_3,param_4);
  return;
}

