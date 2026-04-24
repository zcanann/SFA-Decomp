// Function: FUN_80170518
// Entry: 80170518
// Size: 444 bytes

void FUN_80170518(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = *(int *)(param_9 + 0x5c);
  iVar3 = *(int *)(param_9 + 0x26);
  iVar1 = *(int *)(iVar4 + 0x10);
  if (iVar1 == 2) {
    iVar1 = FUN_80080434((float *)(iVar4 + 4));
    if (iVar1 == 0) {
      FUN_80036018((int)param_9);
      FUN_80035eec((int)param_9,(char)*(undefined4 *)(&DAT_80321618 + *(char *)(iVar3 + 0x19) * 0xc)
                   ,1,0);
      FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                   (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                   (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
      FUN_80035a6c((int)param_9,
                   (short)(int)(*(float *)(iVar4 + 0xc) *
                               (((float)((double)CONCAT44(0x43300000,DAT_803dc9cc ^ 0x80000000) -
                                        DOUBLE_803e4030) - *(float *)(iVar4 + 4)) /
                               (float)((double)CONCAT44(0x43300000,DAT_803dc9cc ^ 0x80000000) -
                                      DOUBLE_803e4030))));
    }
    else {
      uVar5 = FUN_80035ff8((int)param_9);
      FUN_80220088(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  else if ((iVar1 < 2) && (0 < iVar1)) {
    *(float *)(param_9 + 0x12) = FLOAT_803e4024;
    uVar2 = FUN_80022264(100,0x96);
    *(float *)(param_9 + 0x16) =
         FLOAT_803dc9d0 *
         FLOAT_803e4028 *
         *(float *)(iVar4 + 8) *
         FLOAT_803e402c * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4030)
    ;
    FUN_80021b8c(param_9,(float *)(param_9 + 0x12));
    *(float *)(iVar4 + 0xc) = FLOAT_803dc9d4 * *(float *)(iVar4 + 8);
    FUN_80080404((float *)(iVar4 + 4),(short)DAT_803dc9cc);
    *(undefined4 *)(iVar4 + 0x10) = 2;
  }
  return;
}

