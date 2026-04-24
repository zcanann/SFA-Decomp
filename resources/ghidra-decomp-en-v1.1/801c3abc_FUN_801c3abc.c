// Function: FUN_801c3abc
// Entry: 801c3abc
// Size: 264 bytes

void FUN_801c3abc(undefined2 *param_1,int param_2)

{
  int iVar1;
  int *piVar2;
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
  *(code **)(param_1 + 0x5e) = FUN_801c321c;
  FUN_80037a5c((int)param_1,4);
  FUN_800201ac(0x129,1);
  *(undefined *)((int)piVar3 + 0x1b) = 0;
  piVar3[1] = (int)FLOAT_803e5b24;
  iVar1 = FUN_8004832c(0x1f);
  FUN_80043604(iVar1,1,0);
  if (*piVar3 == 0) {
    piVar2 = FUN_8001f58c(0,'\x01');
    *piVar3 = (int)piVar2;
  }
  *(undefined4 *)(param_1 + 0x7a) = 1;
  FUN_800201ac(0xe70,1);
  FUN_800201ac(0xefa,1);
  return;
}

