// Function: FUN_802126d8
// Entry: 802126d8
// Size: 344 bytes

void FUN_802126d8(int param_1,undefined2 param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  float *pfVar4;
  undefined4 uVar5;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  iVar1 = param_3 * 4;
  uVar2 = *(uint *)(DAT_803de9d4 + iVar1 + 0x17c);
  if (uVar2 != 0) {
    FUN_800238c4(uVar2);
    *(undefined4 *)(DAT_803de9d4 + iVar1 + 0x17c) = 0;
  }
  piVar3 = (int *)FUN_8002b660(param_1);
  local_38 = FLOAT_803e7450;
  local_34 = FLOAT_803e7450;
  local_30 = FLOAT_803e7450;
  uVar2 = FUN_80022264(0,*(byte *)(*piVar3 + 0xf3) - 1);
  pfVar4 = (float *)FUN_80028630(piVar3,uVar2);
  FUN_80247bf8(pfVar4,&local_38,&local_20);
  local_20 = local_20 + FLOAT_803dda58;
  local_1c = local_1c + FLOAT_803e7454;
  local_18 = local_18 + FLOAT_803dda5c;
  uVar2 = FUN_80022264(0,*(byte *)(*piVar3 + 0xf3) - 1);
  pfVar4 = (float *)FUN_80028630(piVar3,uVar2);
  FUN_80247bf8(pfVar4,&local_38,local_2c);
  local_2c[0] = local_2c[0] + FLOAT_803dda58;
  local_24 = local_24 + FLOAT_803dda5c;
  uVar5 = FUN_8008fdac((double)FLOAT_803e744c,(double)FLOAT_803e7458,&local_20,local_2c,param_2,0x60
                       ,0);
  *(undefined4 *)(DAT_803de9d4 + iVar1 + 0x17c) = uVar5;
  return;
}

