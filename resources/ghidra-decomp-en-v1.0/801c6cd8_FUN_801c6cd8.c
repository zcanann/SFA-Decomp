// Function: FUN_801c6cd8
// Entry: 801c6cd8
// Size: 300 bytes

void FUN_801c6cd8(undefined2 *param_1,int param_2)

{
  undefined uVar2;
  int iVar1;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  DAT_803ddbc0 = 0;
  DAT_803ddbc4 = (undefined2 *)0x0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)((int)piVar3 + 0x2f) = 0;
  *(undefined *)(piVar3 + 0xc) = 0;
  piVar3[1] = (int)FLOAT_803e4fcc;
  *(undefined2 *)(piVar3 + 8) = 0;
  *(undefined2 *)((int)piVar3 + 0x22) = 0;
  *(undefined2 *)(piVar3 + 9) = 0;
  *(undefined2 *)((int)piVar3 + 0x26) = 0xffff;
  *(undefined *)((int)piVar3 + 0x2e) = 0;
  piVar3[0xd] = 0;
  *(code **)(param_1 + 0x5e) = FUN_801c5ce4;
  FUN_80037964(param_1,4);
  FUN_800200e8(0xba5,1);
  FUN_800200e8(0x129,1);
  FUN_800200e8(0x143,0);
  *(undefined2 *)(piVar3 + 6) = 0xc;
  *(undefined2 *)(piVar3 + 7) = 0x1e;
  piVar3[2] = (int)FLOAT_803e4fd0;
  *(undefined2 *)((int)piVar3 + 0x1a) = 0;
  *(undefined2 *)((int)piVar3 + 0x1e) = 0;
  uVar2 = FUN_8001ffb4(0x58b);
  *(undefined *)((int)piVar3 + 0x32) = uVar2;
  DAT_803ddbc4 = param_1;
  FUN_80037200(param_1,0xb);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar3 == 0) {
    iVar1 = FUN_8001f4c8(0,1);
    *piVar3 = iVar1;
  }
  FUN_800200e8(0xefa,1);
  return;
}

