// Function: FUN_801fd3a4
// Entry: 801fd3a4
// Size: 720 bytes

void FUN_801fd3a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  double dVar5;
  
  cVar1 = *(char *)(*(int *)(param_9 + 0x4c) + 0x19);
  if (cVar1 == '\x02') {
    iVar3 = *(int *)(param_9 + 0xb8);
    DAT_803de944 = DAT_803de944 - (short)(int)FLOAT_803dc074;
    uVar2 = FUN_80020078((int)*(short *)(iVar3 + 2));
    if (((uVar2 == 0) && (DAT_803de944 < 0xc9)) &&
       ((*(char *)(iVar3 + 0xb) == DAT_803de946 && (uVar2 = FUN_80022264(0,2), uVar2 == 0)))) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
    }
  }
  else if (*(short *)(param_9 + 0x46) == 0x3c5) {
    iVar3 = *(int *)(param_9 + 0xb8);
    *(short *)(iVar3 + 6) = *(short *)(iVar3 + 6) - (short)(int)FLOAT_803dc074;
    *(float *)(param_9 + 0xc) =
         *(float *)(param_9 + 0x24) * FLOAT_803dc074 + *(float *)(param_9 + 0xc);
    *(float *)(param_9 + 0x10) =
         *(float *)(param_9 + 0x28) * FLOAT_803dc074 + *(float *)(param_9 + 0x10);
    dVar5 = (double)FLOAT_803dc074;
    *(float *)(param_9 + 0x14) =
         (float)((double)*(float *)(param_9 + 0x2c) * dVar5 + (double)*(float *)(param_9 + 0x14));
    if (*(short *)(iVar3 + 6) < 1) {
      FUN_8002cc9c(dVar5,(double)*(float *)(param_9 + 0x2c),param_3,param_4,param_5,param_6,param_7,
                   param_8,param_9);
    }
  }
  else if (cVar1 == '\0') {
    iVar3 = *(int *)(param_9 + 0xb8);
    DAT_803de944 = DAT_803de944 - (short)(int)FLOAT_803dc074;
    uVar2 = FUN_80020078(0x522);
    if ((((uVar2 == 0) && (DAT_803de944 < 0xc9)) && (*(char *)(iVar3 + 0xb) == DAT_803de946)) &&
       (uVar2 = FUN_80022264(0,2), uVar2 == 0)) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
    }
  }
  else if (cVar1 == '\x01') {
    psVar4 = *(short **)(param_9 + 0xb8);
    uVar2 = FUN_80020078((int)*psVar4);
    if (uVar2 != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x390,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x390,0,4,0xffffffff,0);
      uVar2 = FUN_80022264(0,1);
      if (uVar2 != 0) {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x391,0,4,0xffffffff,0);
      }
    }
    iVar3 = FUN_80036974(param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((short)iVar3 != 0) {
      uVar2 = FUN_80020078((int)*psVar4);
      FUN_800201ac((int)*psVar4,1 - uVar2);
    }
  }
  return;
}

