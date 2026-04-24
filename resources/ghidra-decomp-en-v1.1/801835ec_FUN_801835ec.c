// Function: FUN_801835ec
// Entry: 801835ec
// Size: 368 bytes

void FUN_801835ec(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  FUN_80035ff8((int)param_1);
  FUN_800372f8((int)param_1,0x10);
  if (*(short *)(param_2 + 0x1c) == 0) {
    *(undefined4 *)(iVar2 + 0x18) = 0;
  }
  else {
    *(int *)(iVar2 + 0x18) = *(short *)(param_2 + 0x1c) * 0x3c;
  }
  DAT_803de740 = FUN_80013ee8(0x5b);
  uVar1 = FUN_80022264(0,100);
  *(short *)(iVar2 + 0xe) = (short)uVar1 + 300;
  *(char *)(iVar2 + 0x1f) = (char)*(undefined2 *)(param_2 + 0x1a);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)(iVar2 + 0x1c) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(iVar2 + 0xc) = *(undefined2 *)(param_2 + 0x20);
  if (*(short *)(iVar2 + 0xc) == 0) {
    *(undefined2 *)(iVar2 + 0xc) = 0x14;
  }
  *(undefined2 *)(iVar2 + 0x12) = 800;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(undefined *)(iVar2 + 0x1e) = *(undefined *)(param_2 + 0x19);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 10);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1c));
  if (uVar1 != 0) {
    *(undefined4 *)(iVar2 + 0x14) = 1;
    FUN_80035ff8((int)param_1);
  }
  if (param_1[0x23] == 0x3cf) {
    *(undefined2 *)(iVar2 + 0x10) = 0x60;
  }
  else if (param_1[0x23] == 0x662) {
    *(undefined *)(iVar2 + 0x20) = 1;
    *(undefined2 *)(iVar2 + 0x10) = 0x37d;
  }
  else {
    *(undefined2 *)(iVar2 + 0x10) = 0x4a;
  }
  return;
}

