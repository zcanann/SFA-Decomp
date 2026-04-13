// Function: FUN_8022994c
// Entry: 8022994c
// Size: 360 bytes

void FUN_8022994c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar4;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  *(undefined **)(param_9 + 0x5e) = &LAB_802295a0;
  *(undefined *)((int)param_9 + 0xad) = *(undefined *)(param_10 + 0x19);
  if (*(char *)(*(int *)(param_9 + 0x28) + 0x55) <= *(char *)((int)param_9 + 0xad)) {
    *(undefined *)((int)param_9 + 0xad) = 0;
  }
  uVar1 = FUN_80020078((int)*(short *)(param_10 + 0x20));
  if (uVar1 != 0) {
    uVar1 = FUN_80020078((int)*(short *)(param_10 + 0x1e));
    if (uVar1 == 0) {
      *(undefined *)((int)piVar4 + 6) = 1;
    }
    else {
      *(undefined *)((int)piVar4 + 6) = 2;
    }
  }
  *(undefined *)(param_9 + 0x1b) = 1;
  *(undefined2 *)(piVar4 + 1) = 0xff;
  iVar2 = FUN_8002b660((int)param_9);
  FUN_800285f0(iVar2,FUN_80028590);
  piVar3 = FUN_8001f58c((int)param_9,'\x01');
  *piVar4 = (int)piVar3;
  if (*piVar4 != 0) {
    FUN_8001dbf0(*piVar4,2);
    if (*(char *)((int)param_9 + 0xad) == '\0') {
      FUN_8001d7f4((double)FLOAT_803e7ad4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *piVar4,0,0xff,0xff,0x4d,0x96,in_r9,in_r10);
    }
    else {
      FUN_8001d7f4((double)FLOAT_803e7ad4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *piVar4,0,0x4d,0x4d,0xff,0xff,in_r9,in_r10);
    }
    FUN_8001d7d8((double)FLOAT_803e7ad8,*piVar4);
  }
  return;
}

