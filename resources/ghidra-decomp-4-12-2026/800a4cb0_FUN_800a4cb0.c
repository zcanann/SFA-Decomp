// Function: FUN_800a4cb0
// Entry: 800a4cb0
// Size: 388 bytes

void FUN_800a4cb0(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,
                 undefined2 *param_5)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  float *pfVar4;
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
  
  uVar6 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  piVar2 = (int *)FUN_8002b660(iVar1);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(*piVar2 + 0xf3); iVar5 = iVar5 + 1) {
    uVar3 = FUN_80022264(1,100);
    if ((int)uVar3 <= (int)(param_4 & 0xff)) {
      local_2c = FLOAT_803e0128;
      local_28 = FLOAT_803e0128;
      local_24 = FLOAT_803e0128;
      local_30 = FLOAT_803e0138;
      local_34 = 0;
      local_36 = 0;
      local_38 = 0;
      pfVar4 = (float *)FUN_80028630(piVar2,iVar5);
      FUN_80247bf8(pfVar4,&local_2c,&local_2c);
      local_28 = local_28 - *(float *)(iVar1 + 0x1c);
      local_2c = (local_2c - *(float *)(iVar1 + 0x18)) + FLOAT_803dda58;
      local_24 = (local_24 - *(float *)(iVar1 + 0x20)) + FLOAT_803dda5c;
      if (param_5 == (undefined2 *)0x0) {
        local_30 = FLOAT_803e0138;
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
      (**(code **)(*DAT_803dd708 + 8))(iVar1,(int)uVar6,&local_38,2,0xffffffff,param_3);
    }
  }
  FUN_80286880();
  return;
}

