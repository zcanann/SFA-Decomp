// Function: FUN_8016b78c
// Entry: 8016b78c
// Size: 780 bytes

void FUN_8016b78c(uint param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 local_28;
  undefined4 local_24;
  undefined8 local_20;
  undefined8 local_18;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar2 = (uint)*(byte *)(param_1 + 0x36);
  if (uVar2 < 0xff) {
    local_20 = (double)CONCAT44(0x43300000,uVar2);
    dVar6 = (double)(float)(local_20 - DOUBLE_803e3e50);
    in_f4 = (double)(FLOAT_803e3e5c * FLOAT_803dc074);
    if ((float)(dVar6 - in_f4) <= FLOAT_803e3e60) {
      dVar7 = DOUBLE_803e3e50;
      uVar5 = FUN_8000b7dc(param_1,0x7f);
      *(undefined *)(param_1 + 0x36) = 0;
      FUN_8002cc9c(uVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
      return;
    }
    local_20 = (double)CONCAT44(0x43300000,uVar2);
    iVar1 = (int)((double)(float)(local_20 - DOUBLE_803e3e50) - in_f4);
    local_18 = (double)(longlong)iVar1;
    *(char *)(param_1 + 0x36) = (char)iVar1;
  }
  else {
    *(float *)(param_1 + 0x28) = -(FLOAT_803e3e64 * FLOAT_803dc074 - *(float *)(param_1 + 0x28));
    if (*(float *)(param_1 + 0x28) < FLOAT_803e3e68) {
      *(float *)(param_1 + 0x28) = FLOAT_803e3e68;
    }
    FUN_8002ba34((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x28) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
  }
  if ((*(char *)(param_1 + 0x36) == -1) || (*(char *)(iVar3 + 0xc) != '\0')) {
    FUN_80035eec(param_1,5,1,0);
    FUN_80036018(param_1);
    if ((*(int *)(*(int *)(param_1 + 0x54) + 0x50) == 0) ||
       (iVar1 = FUN_8002bac4(), *(int *)(*(int *)(param_1 + 0x54) + 0x50) != iVar1)) {
      if ((*(float *)(param_1 + 0x10) <= *(float *)(iVar3 + 4)) && (*(char *)(param_1 + 0x36) == -1)
         ) {
        piVar4 = *(int **)(param_1 + 0xb8);
        local_28 = DAT_803e3e38;
        FUN_8000bb38(param_1,0x4a);
        uVar2 = FUN_80022264(0,2);
        (**(code **)(*(int *)piVar4[2] + 4))(param_1,uVar2,0,2,0xffffffff,&local_28);
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62));
        iVar1 = (int)(FLOAT_803e3e3c * (float)(local_18 - DOUBLE_803e3e50));
        local_20 = (double)(longlong)iVar1;
        FUN_80035a6c(param_1,(short)iVar1);
        dVar6 = (double)FLOAT_803e3e44;
        dVar7 = (double)FLOAT_803e3e48;
        uVar5 = FUN_8000e670((double)FLOAT_803e3e40,dVar6,dVar7);
        *(undefined *)(param_1 + 0x36) = 0xfe;
        FUN_8002cc9c(uVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar4);
        *piVar4 = 0;
        *(undefined *)(iVar3 + 0xc) = 1;
      }
    }
    else {
      if (*(char *)(param_1 + 0x36) == -1) {
        piVar4 = *(int **)(param_1 + 0xb8);
        local_24 = DAT_803e3e38;
        FUN_8000bb38(param_1,0x4a);
        uVar2 = FUN_80022264(0,2);
        (**(code **)(*(int *)piVar4[2] + 4))(param_1,uVar2,0,2,0xffffffff,&local_24);
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62));
        iVar3 = (int)(FLOAT_803e3e3c * (float)(local_18 - DOUBLE_803e3e50));
        local_20 = (double)(longlong)iVar3;
        FUN_80035a6c(param_1,(short)iVar3);
        dVar6 = (double)FLOAT_803e3e44;
        dVar7 = (double)FLOAT_803e3e48;
        uVar5 = FUN_8000e670((double)FLOAT_803e3e40,dVar6,dVar7);
        *(undefined *)(param_1 + 0x36) = 0xfe;
        FUN_8002cc9c(uVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar4);
        *piVar4 = 0;
      }
      FUN_80035ff8(param_1);
    }
  }
  return;
}

