// Function: FUN_801f1ad0
// Entry: 801f1ad0
// Size: 284 bytes

void FUN_801f1ad0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined4 uVar3;
  int *piVar4;
  undefined8 uVar5;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  uVar5 = FUN_80037a5c((int)param_9,2);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  if (*(short *)(param_10 + 0x1c) == 0) {
    uVar3 = 0x50;
    uVar1 = FUN_80022264(0xffffffb0,0x50);
    *(short *)(piVar4 + 0xc) = (short)uVar1 + 400;
  }
  else {
    *(short *)(piVar4 + 0xc) = *(short *)(param_10 + 0x1c);
    uVar3 = extraout_r4;
  }
  *(undefined2 *)(piVar4 + 0xb) = *(undefined2 *)(piVar4 + 0xc);
  *(undefined *)((int)piVar4 + 0x4d) = 0;
  piVar4[7] = (int)FLOAT_803e69a8;
  *(undefined *)((int)piVar4 + 0x4e) = *(undefined *)(param_10 + 0x19);
  *(undefined2 *)((int)piVar4 + 0x2e) = 0x118;
  *(undefined2 *)((int)piVar4 + 0x32) = 0xffff;
  if (*(char *)((int)piVar4 + 0x4e) == '\x1e') {
    if (*piVar4 == 0) {
      iVar2 = FUN_80054ed0(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3e9,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*(char *)((int)piVar4 + 0x4e) == '\x01') {
    if (*piVar4 == 0) {
      iVar2 = FUN_80054ed0(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x23d,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*piVar4 == 0) {
    iVar2 = FUN_80054ed0(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xd9,uVar3,
                         param_11,param_12,param_13,param_14,param_15,param_16);
    *piVar4 = iVar2;
  }
  return;
}

