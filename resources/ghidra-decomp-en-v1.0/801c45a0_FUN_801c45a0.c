// Function: FUN_801c45a0
// Entry: 801c45a0
// Size: 188 bytes

void FUN_801c45a0(undefined2 *param_1,int param_2)

{
  short sVar2;
  int iVar1;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  FUN_80037964(param_1,2);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  sVar2 = FUN_800221a0(0xffffffb0,0x50);
  *(short *)(piVar3 + 0xb) = sVar2 + 400;
  *(undefined *)((int)piVar3 + 0x49) = 0;
  DAT_803ddbb8 = FUN_80013ec8(0x81,1);
  piVar3[7] = (int)FLOAT_803e4ec0;
  *(undefined *)((int)piVar3 + 0x4a) = *(undefined *)(param_2 + 0x19);
  *(undefined2 *)((int)piVar3 + 0x2e) = 0x118;
  if (*piVar3 == 0) {
    iVar1 = FUN_80054d54(0x2e);
    *piVar3 = iVar1;
  }
  return;
}

