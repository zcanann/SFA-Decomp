// Function: FUN_8014f9e8
// Entry: 8014f9e8
// Size: 992 bytes

void FUN_8014f9e8(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  undefined4 local_48;
  undefined auStack68 [4];
  undefined auStack64 [4];
  float local_3c;
  float local_38;
  float local_34;
  undefined auStack48 [4];
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack28;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  iVar2 = *piVar3;
  iVar1 = FUN_80036770(param_1,auStack48,auStack64,auStack68,&local_34,&local_38,&local_3c);
  if (iVar1 != 0) {
    piVar3[2] = (int)FLOAT_803e2708;
    if ((*(byte *)(piVar3 + 9) & 2) != 0) {
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) & 0xfd;
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) | 4;
    }
    FUN_8000bae0((double)local_34,(double)local_38,(double)local_3c,param_1,0x23c);
  }
  local_48 = 4;
  (**(code **)(*DAT_803dca88 + 8))(param_1,piVar3[8],0,1,0xffffffff,&local_48);
  local_48 = 3;
  (**(code **)(*DAT_803dca88 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
  if ((float)piVar3[3] <= (float)piVar3[2]) {
    piVar3[2] = piVar3[3];
    local_48 = 2;
    (**(code **)(*DAT_803dca88 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
    local_48 = 0;
    (**(code **)(*DAT_803dca88 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
    FUN_80035df4(param_1,10,1,0);
    FUN_80035f20(param_1);
  }
  else {
    piVar3[2] = (int)((float)piVar3[2] + FLOAT_803e270c);
    FUN_80035f00(param_1);
  }
  local_48 = 1;
  (**(code **)(*DAT_803dca88 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
  iVar1 = FUN_8002b9ec();
  piVar3[1] = iVar1;
  iVar1 = piVar3[1];
  if (iVar1 != 0) {
    local_2c = *(float *)(iVar1 + 0x18) - *(float *)(param_1 + 0x18);
    local_28 = *(float *)(iVar1 + 0x1c) - *(float *)(param_1 + 0x1c);
    local_24 = *(float *)(iVar1 + 0x20) - *(float *)(param_1 + 0x20);
    dVar4 = (double)FUN_802931a0((double)(local_24 * local_24 +
                                         local_2c * local_2c + local_28 * local_28));
    piVar3[4] = (int)(float)dVar4;
  }
  if (iVar2 != 0) {
    local_2c = *(float *)(iVar2 + 0x68) - *(float *)(param_1 + 0x18);
    local_28 = *(float *)(iVar2 + 0x6c) - *(float *)(param_1 + 0x1c);
    local_24 = *(float *)(iVar2 + 0x70) - *(float *)(param_1 + 0x20);
    dVar4 = (double)FUN_802931a0((double)(local_24 * local_24 +
                                         local_2c * local_2c + local_28 * local_28));
    piVar3[5] = (int)(float)dVar4;
  }
  if ((*(byte *)(piVar3 + 9) & 2) != 0) {
    if (FLOAT_803e2710 < (float)piVar3[5]) {
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) & 0xfd;
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) | 4;
    }
    piVar3[7] = (int)((float)piVar3[7] - FLOAT_803db414);
    if ((float)piVar3[7] < FLOAT_803e2714) {
      FUN_8000bb18(param_1,0x23d);
      uStack28 = FUN_800221a0(0x3c,0x78);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      piVar3[7] = (int)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e2700);
    }
    piVar3[8] = 0x338;
  }
  if ((*(byte *)(piVar3 + 9) & 4) != 0) {
    if ((float)piVar3[5] < FLOAT_803e2718) {
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) & 0xfb;
    }
    piVar3[8] = 0x337;
  }
  if ((*(byte *)(piVar3 + 9) & 6) == 0) {
    if ((((float)piVar3[3] <= (float)piVar3[2]) && (piVar3[1] != 0)) &&
       ((float)piVar3[4] < (float)piVar3[6])) {
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) | 2;
    }
    piVar3[8] = 0x337;
  }
  FUN_8014f620(param_1,piVar3);
  return;
}

