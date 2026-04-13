// Function: FUN_801c4b54
// Entry: 801c4b54
// Size: 188 bytes

void FUN_801c4b54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  piVar3 = *(int **)(param_9 + 0x5c);
  FUN_80037a5c((int)param_9,2);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  uVar1 = FUN_80022264(0xffffffb0,0x50);
  *(short *)(piVar3 + 0xb) = (short)uVar1 + 400;
  *(undefined *)((int)piVar3 + 0x49) = 0;
  uVar4 = FUN_80013ee8(0x81);
  DAT_803de838 = (undefined4)((ulonglong)uVar4 >> 0x20);
  piVar3[7] = (int)FLOAT_803e5b58;
  *(undefined *)((int)piVar3 + 0x4a) = *(undefined *)(param_10 + 0x19);
  *(undefined2 *)((int)piVar3 + 0x2e) = 0x118;
  if (*piVar3 == 0) {
    iVar2 = FUN_80054ed0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2e,
                         (int)uVar4,param_11,param_12,param_13,param_14,param_15,param_16);
    *piVar3 = iVar2;
  }
  return;
}

