// Function: FUN_8020b55c
// Entry: 8020b55c
// Size: 500 bytes

void FUN_8020b55c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  float fStack_28;
  undefined4 uStack_24;
  undefined4 auStack_20 [5];
  
  iVar5 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(param_9 + 0x4c);
  iVar2 = FUN_80036868(param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0,&fStack_28,&uStack_24,
                       auStack_20);
  if ((iVar2 == 0xf) || (iVar2 == 0xe)) {
    if ((*(byte *)(iVar5 + 0x198) >> 6 & 1) == 0) {
      if (*(float *)(iVar5 + 0x1a0) < FLOAT_803e71a8) {
        *(float *)(iVar5 + 0x1a0) = FLOAT_803e71b8;
        FUN_8000bb38(param_9,0x4b0);
      }
    }
    else {
      *(int *)(iVar5 + 0x170) = *(int *)(iVar5 + 0x170) + -1;
      *(byte *)(iVar5 + 0x198) = *(byte *)(iVar5 + 0x198) & 0xf7 | 8;
      if (*(int *)(iVar5 + 0x170) < 0) {
        FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
        FUN_8009adfc((double)FLOAT_803e71e8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,1,1,1,1,1,1);
        FUN_8002cf80(param_9);
        (**(code **)(*DAT_803dd72c + 0x44))(0x1d,3);
        FUN_800201ac(0x83c,1);
      }
      else {
        FUN_802224e4(param_9,&fStack_28);
      }
      if (*(float *)(iVar5 + 0x19c) <= FLOAT_803e71a8) {
        *(float *)(iVar5 + 0x19c) = FLOAT_803e71f0;
        FUN_8000bb38(param_9,0x478);
      }
      if (*(float *)(iVar5 + 0x1a0) <= FLOAT_803e71a8) {
        *(float *)(iVar5 + 0x1a0) = FLOAT_803e71b8;
        FUN_8000bb38(param_9,0x4af);
      }
      fVar1 = FLOAT_803e71b0;
      *(float *)(iVar5 + 0x17c) = FLOAT_803e71b0;
      *(float *)(iVar5 + 0x178) = fVar1;
      uVar3 = FUN_80022264(0xffffffce,0x32);
      *(float *)(iVar5 + 0x180) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e71c0) /
           FLOAT_803e71f4;
    }
  }
  *(float *)(iVar5 + 0x19c) = *(float *)(iVar5 + 0x19c) - FLOAT_803dc074;
  *(float *)(iVar5 + 0x1a0) = *(float *)(iVar5 + 0x1a0) - FLOAT_803dc074;
  return;
}

