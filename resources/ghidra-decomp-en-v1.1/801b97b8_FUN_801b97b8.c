// Function: FUN_801b97b8
// Entry: 801b97b8
// Size: 496 bytes

void FUN_801b97b8(undefined2 *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar3 + 0xa0) = *(undefined4 *)(param_2 + 0x14);
  *(float *)(iVar3 + 0xa4) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
              DOUBLE_803e57f8) / FLOAT_803e57e0;
  uVar2 = FUN_80022264(0xffffffe2,0x1e);
  *(float *)(iVar3 + 0xa8) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  uVar2 = FUN_80022264(0,(int)*(char *)(*(int *)(param_1 + 0x28) + 0x55) - 1);
  *(char *)((int)param_1 + 0xad) = (char)uVar2;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar2 = FUN_80022264(0,0xffff);
  *param_1 = (short)uVar2;
  *(undefined *)(param_1 + 0x1b) = 0;
  sVar1 = param_1[0x23];
  if (sVar1 == 0x10d) {
    uVar2 = FUN_80022264(0,0x32);
    *(float *)(iVar3 + 0xac) =
         FLOAT_803e57ec + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8)
    ;
    *(float *)(iVar3 + 0xb0) = FLOAT_803e57e8;
  }
  else if ((sVar1 < 0x10d) && (sVar1 == 0x109)) {
    uVar2 = FUN_80022264(0,0x28);
    *(float *)(iVar3 + 0xac) =
         FLOAT_803e57e4 + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8)
    ;
    *(float *)(iVar3 + 0xb0) = FLOAT_803e57e8;
  }
  else {
    uVar2 = FUN_80022264(0,0x28);
    *(float *)(iVar3 + 0xac) =
         FLOAT_803e57f0 + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e57f8)
    ;
    *(float *)(iVar3 + 0xb0) = FLOAT_803e57e8;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

