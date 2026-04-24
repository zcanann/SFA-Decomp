// Function: FUN_801f1498
// Entry: 801f1498
// Size: 284 bytes

void FUN_801f1498(undefined2 *param_1,int param_2)

{
  short sVar2;
  int iVar1;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  FUN_80037964(param_1,2);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if (*(short *)(param_2 + 0x1c) == 0) {
    sVar2 = FUN_800221a0(0xffffffb0,0x50);
    *(short *)(piVar3 + 0xc) = sVar2 + 400;
  }
  else {
    *(short *)(piVar3 + 0xc) = *(short *)(param_2 + 0x1c);
  }
  *(undefined2 *)(piVar3 + 0xb) = *(undefined2 *)(piVar3 + 0xc);
  *(undefined *)((int)piVar3 + 0x4d) = 0;
  piVar3[7] = (int)FLOAT_803e5d10;
  *(undefined *)((int)piVar3 + 0x4e) = *(undefined *)(param_2 + 0x19);
  *(undefined2 *)((int)piVar3 + 0x2e) = 0x118;
  *(undefined2 *)((int)piVar3 + 0x32) = 0xffff;
  if (*(char *)((int)piVar3 + 0x4e) == '\x1e') {
    if (*piVar3 == 0) {
      iVar1 = FUN_80054d54(0x3e9);
      *piVar3 = iVar1;
    }
  }
  else if (*(char *)((int)piVar3 + 0x4e) == '\x01') {
    if (*piVar3 == 0) {
      iVar1 = FUN_80054d54(0x23d);
      *piVar3 = iVar1;
    }
  }
  else if (*piVar3 == 0) {
    iVar1 = FUN_80054d54(0xd9);
    *piVar3 = iVar1;
  }
  return;
}

