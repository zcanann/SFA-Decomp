// Function: FUN_801c3508
// Entry: 801c3508
// Size: 264 bytes

void FUN_801c3508(undefined2 *param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)(piVar3 + 4) = 10;
  if (0 < *(short *)(param_2 + 0x1a)) {
    *(short *)(piVar3 + 4) = *(short *)(param_2 + 0x1a) >> 8;
  }
  *(undefined *)((int)piVar3 + 0x1a) = 4;
  *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) & 0x7f;
  *(undefined2 *)((int)piVar3 + 0x12) = 0;
  *(code **)(param_1 + 0x5e) = FUN_801c2c68;
  FUN_80037964(param_1,4);
  FUN_800200e8(0x129,1);
  *(undefined *)((int)piVar3 + 0x1b) = 0;
  piVar3[1] = (int)FLOAT_803e4e8c;
  uVar1 = FUN_800481b0(0x1f);
  FUN_8004350c(uVar1,1,0);
  if (*piVar3 == 0) {
    iVar2 = FUN_8001f4c8(0,1);
    *piVar3 = iVar2;
  }
  *(undefined4 *)(param_1 + 0x7a) = 1;
  FUN_800200e8(0xe70,1);
  FUN_800200e8(0xefa,1);
  return;
}

