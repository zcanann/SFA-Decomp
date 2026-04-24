// Function: FUN_800a4a24
// Entry: 800a4a24
// Size: 388 bytes

void FUN_800a4a24(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,
                 undefined2 *param_5)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  uVar6 = FUN_802860d0();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  piVar2 = (int *)FUN_8002b588();
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(*piVar2 + 0xf3); iVar5 = iVar5 + 1) {
    iVar3 = FUN_800221a0(1,100);
    if (iVar3 <= (int)(param_4 & 0xff)) {
      local_2c = FLOAT_803df4a8;
      local_28 = FLOAT_803df4a8;
      local_24 = FLOAT_803df4a8;
      local_30 = FLOAT_803df4b8;
      local_34 = 0;
      local_36 = 0;
      local_38 = 0;
      uVar4 = FUN_8002856c(piVar2,iVar5);
      FUN_80247494(uVar4,&local_2c,&local_2c);
      local_28 = local_28 - *(float *)(iVar1 + 0x1c);
      local_2c = (local_2c - *(float *)(iVar1 + 0x18)) + FLOAT_803dcdd8;
      local_24 = (local_24 - *(float *)(iVar1 + 0x20)) + FLOAT_803dcddc;
      if (param_5 == (undefined2 *)0x0) {
        local_30 = FLOAT_803df4b8;
        local_38 = 0;
        local_34 = 0;
        local_36 = 0;
        local_32 = 0;
      }
      else {
        local_30 = *(float *)(param_5 + 4);
        local_38 = *param_5;
        local_34 = param_5[2];
        local_36 = param_5[1];
        local_32 = param_5[3];
      }
      (**(code **)(*DAT_803dca88 + 8))(iVar1,(int)uVar6,&local_38,2,0xffffffff,param_3);
    }
  }
  FUN_8028611c();
  return;
}

