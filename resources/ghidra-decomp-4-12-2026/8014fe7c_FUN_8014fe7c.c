// Function: FUN_8014fe7c
// Entry: 8014fe7c
// Size: 992 bytes

void FUN_8014fe7c(uint param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  undefined4 local_48;
  uint uStack_44;
  int iStack_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined4 uStack_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  iVar2 = *piVar3;
  iVar1 = FUN_80036868(param_1,&uStack_30,&iStack_40,&uStack_44,&local_34,&local_38,&local_3c);
  if (iVar1 != 0) {
    piVar3[2] = (int)FLOAT_803e33a0;
    if ((*(byte *)(piVar3 + 9) & 2) != 0) {
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) & 0xfd;
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) | 4;
    }
    FUN_8000bb00((double)local_34,(double)local_38,(double)local_3c,param_1,0x23c);
  }
  local_48 = 4;
  (**(code **)(*DAT_803dd708 + 8))(param_1,piVar3[8],0,1,0xffffffff,&local_48);
  local_48 = 3;
  (**(code **)(*DAT_803dd708 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
  if ((float)piVar3[3] <= (float)piVar3[2]) {
    piVar3[2] = piVar3[3];
    local_48 = 2;
    (**(code **)(*DAT_803dd708 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
    local_48 = 0;
    (**(code **)(*DAT_803dd708 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
    FUN_80035eec(param_1,10,1,0);
    FUN_80036018(param_1);
  }
  else {
    piVar3[2] = (int)((float)piVar3[2] + FLOAT_803e33a4);
    FUN_80035ff8(param_1);
  }
  local_48 = 1;
  (**(code **)(*DAT_803dd708 + 8))(param_1,piVar3[8],0,2,0xffffffff,&local_48);
  iVar1 = FUN_8002bac4();
  piVar3[1] = iVar1;
  iVar1 = piVar3[1];
  if (iVar1 != 0) {
    local_2c = *(float *)(iVar1 + 0x18) - *(float *)(param_1 + 0x18);
    local_28 = *(float *)(iVar1 + 0x1c) - *(float *)(param_1 + 0x1c);
    local_24 = *(float *)(iVar1 + 0x20) - *(float *)(param_1 + 0x20);
    dVar4 = FUN_80293900((double)(local_24 * local_24 + local_2c * local_2c + local_28 * local_28));
    piVar3[4] = (int)(float)dVar4;
  }
  if (iVar2 != 0) {
    local_2c = *(float *)(iVar2 + 0x68) - *(float *)(param_1 + 0x18);
    local_28 = *(float *)(iVar2 + 0x6c) - *(float *)(param_1 + 0x1c);
    local_24 = *(float *)(iVar2 + 0x70) - *(float *)(param_1 + 0x20);
    dVar4 = FUN_80293900((double)(local_24 * local_24 + local_2c * local_2c + local_28 * local_28));
    piVar3[5] = (int)(float)dVar4;
  }
  if ((*(byte *)(piVar3 + 9) & 2) != 0) {
    if (FLOAT_803e33a8 < (float)piVar3[5]) {
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) & 0xfd;
      *(byte *)(piVar3 + 9) = *(byte *)(piVar3 + 9) | 4;
    }
    piVar3[7] = (int)((float)piVar3[7] - FLOAT_803dc074);
    if ((float)piVar3[7] < FLOAT_803e33ac) {
      FUN_8000bb38(param_1,0x23d);
      uStack_1c = FUN_80022264(0x3c,0x78);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      piVar3[7] = (int)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3398);
    }
    piVar3[8] = 0x338;
  }
  if ((*(byte *)(piVar3 + 9) & 4) != 0) {
    if ((float)piVar3[5] < FLOAT_803e33b0) {
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
  FUN_8014fab4(param_1,piVar3);
  return;
}

