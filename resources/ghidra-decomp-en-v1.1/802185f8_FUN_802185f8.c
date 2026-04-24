// Function: FUN_802185f8
// Entry: 802185f8
// Size: 328 bytes

void FUN_802185f8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  int *piVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar2;
  double dVar3;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  FUN_80036018(param_9);
  *(undefined *)(piVar2 + 1) = 4;
  *(undefined2 *)(param_9 + 4) = 0;
  piVar1 = FUN_8001f58c(param_9,'\x01');
  if (piVar1 != (int *)0x0) {
    FUN_8001dbf0((int)piVar1,2);
    FUN_8001dbb4((int)piVar1,0xff,0x80,0,0);
    FUN_8001dbd8((int)piVar1,1);
    dVar3 = (double)FLOAT_803e75dc;
    FUN_8001dcfc((double)FLOAT_803e75d8,dVar3,(int)piVar1);
    FUN_8001d7f4((double)FLOAT_803e75e0,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,piVar1
                 ,0,0,0xff,0xff,0x80,in_r9,in_r10);
    FUN_8001d7d8((double)FLOAT_803e75e4,(int)piVar1);
  }
  *piVar2 = (int)piVar1;
  if (*piVar2 != 0) {
    FUN_8001dcfc((double)FLOAT_803e75e8,(double)FLOAT_803e75ec,*piVar2);
  }
  *(undefined *)(param_9 + 0x36) = 0xff;
  *(float *)(param_9 + 8) = FLOAT_803e75f0 * *(float *)(*(int *)(param_9 + 0x50) + 4);
  piVar2[2] = 0x960;
  FUN_80035a58(param_9,4);
  FUN_80035eec(param_9,0x16,1,0);
  FUN_8000bb38(param_9,0x3c5);
  FUN_8000bb38(param_9,0x3c6);
  return;
}

