// Function: FUN_80183094
// Entry: 80183094
// Size: 368 bytes

void FUN_80183094(undefined2 *param_1,int param_2)

{
  short sVar2;
  int iVar1;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  FUN_80035f00();
  FUN_80037200(param_1,0x10);
  if (*(short *)(param_2 + 0x1c) == 0) {
    *(undefined4 *)(iVar3 + 0x18) = 0;
  }
  else {
    *(int *)(iVar3 + 0x18) = *(short *)(param_2 + 0x1c) * 0x3c;
  }
  DAT_803ddac0 = FUN_80013ec8(0x5b,1);
  sVar2 = FUN_800221a0(0,100);
  *(short *)(iVar3 + 0xe) = sVar2 + 300;
  *(char *)(iVar3 + 0x1f) = (char)*(undefined2 *)(param_2 + 0x1a);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)(iVar3 + 0x1c) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(iVar3 + 0xc) = *(undefined2 *)(param_2 + 0x20);
  if (*(short *)(iVar3 + 0xc) == 0) {
    *(undefined2 *)(iVar3 + 0xc) = 0x14;
  }
  *(undefined2 *)(iVar3 + 0x12) = 800;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined *)(iVar3 + 0x1e) = *(undefined *)(param_2 + 0x19);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 10);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1c));
  if (iVar1 != 0) {
    *(undefined4 *)(iVar3 + 0x14) = 1;
    FUN_80035f00(param_1);
  }
  if (param_1[0x23] == 0x3cf) {
    *(undefined2 *)(iVar3 + 0x10) = 0x60;
  }
  else if (param_1[0x23] == 0x662) {
    *(undefined *)(iVar3 + 0x20) = 1;
    *(undefined2 *)(iVar3 + 0x10) = 0x37d;
  }
  else {
    *(undefined2 *)(iVar3 + 0x10) = 0x4a;
  }
  return;
}

