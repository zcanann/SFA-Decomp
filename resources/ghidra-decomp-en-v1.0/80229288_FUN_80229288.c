// Function: FUN_80229288
// Entry: 80229288
// Size: 360 bytes

void FUN_80229288(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined **)(param_1 + 0x5e) = &LAB_80228edc;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x20));
  if (iVar1 != 0) {
    iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
    if (iVar1 == 0) {
      *(undefined *)((int)piVar3 + 6) = 1;
    }
    else {
      *(undefined *)((int)piVar3 + 6) = 2;
    }
  }
  *(undefined *)(param_1 + 0x1b) = 1;
  *(undefined2 *)(piVar3 + 1) = 0xff;
  uVar2 = FUN_8002b588(param_1);
  FUN_8002852c(uVar2,FUN_800284cc);
  iVar1 = FUN_8001f4c8(param_1,1);
  *piVar3 = iVar1;
  if (*piVar3 != 0) {
    FUN_8001db2c(*piVar3,2);
    if (*(char *)((int)param_1 + 0xad) == '\0') {
      FUN_8001d730((double)FLOAT_803e6e3c,*piVar3,0,0xff,0xff,0x4d,0x96);
    }
    else {
      FUN_8001d730((double)FLOAT_803e6e3c,*piVar3,0,0x4d,0x4d,0xff,0xff);
    }
    FUN_8001d714((double)FLOAT_803e6e40,*piVar3);
  }
  return;
}

