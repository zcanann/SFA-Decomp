// Function: FUN_8015be64
// Entry: 8015be64
// Size: 328 bytes

undefined4
FUN_8015be64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e39c0;
  fVar1 = FLOAT_803e39ac;
  dVar4 = (double)FLOAT_803e39ac;
  *(float *)(param_10 + 0x280) = FLOAT_803e39ac;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,param_12,
                 param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(byte *)(param_10 + 0x356) & 1) == 0) {
    iVar2 = FUN_8002bac4();
    if (*(short *)(iVar2 + 0x46) == 0) {
      FUN_8000bb38(param_9,0x239);
    }
    else {
      FUN_8000bb38(param_9,0x1f2);
    }
    FUN_8000bb38(param_9,0x232);
    FUN_8000bb38(param_9,0x26f);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
  }
  if (((*(byte *)(param_10 + 0x356) & 2) == 0) && (FLOAT_803e39c4 < *(float *)(param_9 + 0x98))) {
    FUN_8000bb38(param_9,0x233);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 2;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar3 + 0x3f0),0xffffffff,0);
  }
  return 0;
}

