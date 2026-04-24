// Function: FUN_80212060
// Entry: 80212060
// Size: 344 bytes

void FUN_80212060(undefined4 param_1,undefined2 param_2,int param_3)

{
  int *piVar1;
  undefined4 uVar2;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  param_3 = param_3 * 4;
  if (*(int *)(DAT_803ddd54 + param_3 + 0x17c) != 0) {
    FUN_80023800();
    *(undefined4 *)(DAT_803ddd54 + param_3 + 0x17c) = 0;
  }
  piVar1 = (int *)FUN_8002b588(param_1);
  local_38 = FLOAT_803e67b8;
  local_34 = FLOAT_803e67b8;
  local_30 = FLOAT_803e67b8;
  uVar2 = FUN_800221a0(0,*(byte *)(*piVar1 + 0xf3) - 1);
  uVar2 = FUN_8002856c(piVar1,uVar2);
  FUN_80247494(uVar2,&local_38,&local_20);
  local_20 = local_20 + FLOAT_803dcdd8;
  local_1c = local_1c + FLOAT_803e67bc;
  local_18 = local_18 + FLOAT_803dcddc;
  uVar2 = FUN_800221a0(0,*(byte *)(*piVar1 + 0xf3) - 1);
  uVar2 = FUN_8002856c(piVar1,uVar2);
  FUN_80247494(uVar2,&local_38,local_2c);
  local_2c[0] = local_2c[0] + FLOAT_803dcdd8;
  local_24 = local_24 + FLOAT_803dcddc;
  uVar2 = FUN_8008fb20((double)FLOAT_803e67b4,(double)FLOAT_803e67c0,&local_20,local_2c,param_2,0x60
                       ,0);
  *(undefined4 *)(DAT_803ddd54 + param_3 + 0x17c) = uVar2;
  return;
}

