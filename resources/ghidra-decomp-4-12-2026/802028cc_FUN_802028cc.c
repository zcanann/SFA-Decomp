// Function: FUN_802028cc
// Entry: 802028cc
// Size: 404 bytes

undefined4
FUN_802028cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar4 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_1 = FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    if (*(int *)(iVar4 + 0x18) != 0) {
      FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar4 + 0x18),0x11,param_9,0x10,param_13,param_14,param_15,param_16);
      *(undefined4 *)(iVar4 + 0x18) = 0;
    }
    iVar1 = FUN_8002bac4();
    iVar1 = (**(code **)(**(int **)(*(int *)(iVar1 + 200) + 0x68) + 0x44))();
    if (iVar1 == 0) {
      uVar2 = FUN_80022264(0,2);
      FUN_8000bb38(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    else {
      uVar2 = FUN_80022264(3,4);
      FUN_8000bb38(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    local_20 = *(undefined4 *)(iVar4 + 0x30);
    local_24 = *(undefined4 *)(iVar4 + 0x2c);
    psVar3 = *(short **)(iVar4 + 0x24);
    local_28 = *(undefined4 *)(iVar4 + 0x28);
    uVar2 = FUN_800138e4(psVar3);
    if (uVar2 == 0) {
      FUN_80013978(psVar3,(uint)&local_28);
    }
    *(undefined4 *)(iVar4 + 0x3c) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x10;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6fd8;
  *(float *)(param_10 + 0x280) = FLOAT_803e6f40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  return 0;
}

