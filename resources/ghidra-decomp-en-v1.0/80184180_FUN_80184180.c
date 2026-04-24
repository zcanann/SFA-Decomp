// Function: FUN_80184180
// Entry: 80184180
// Size: 568 bytes

void FUN_80184180(undefined2 *param_1,int param_2)

{
  int iVar1;
  short sVar3;
  uint uVar2;
  int *piVar4;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  local_2c = DAT_802c2280;
  local_28 = DAT_802c2284;
  local_24 = DAT_802c2288;
  local_38 = DAT_802c228c;
  local_34 = DAT_802c2290;
  local_30 = DAT_802c2294;
  piVar4 = *(int **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_80183b04;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)((int)piVar4 + 0xe) = *(undefined2 *)(param_2 + 0x1e);
  iVar1 = (int)*(short *)(param_2 + 0x1c);
  if (iVar1 == 0) {
    *piVar4 = 0;
  }
  else if (iVar1 == 0xff) {
    *piVar4 = -1;
  }
  else {
    *piVar4 = iVar1 * 0x3c;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)((int)piVar4 + 0xe));
  if (iVar1 != 0) {
    piVar4[1] = (int)FLOAT_803e39ac;
    FUN_80035f00(param_1);
  }
  *(undefined *)((int)piVar4 + 0x11) = *(undefined *)(param_2 + 0x19);
  DAT_803ddac8 = FUN_80013ec8(0x5b,1);
  sVar3 = FUN_800221a0(0,100);
  *(short *)((int)piVar4 + 10) = sVar3 + 300;
  *(undefined2 *)(piVar4 + 3) = 400;
  *(char *)((int)piVar4 + 0x12) = (char)*(undefined2 *)(param_2 + 0x1a);
  param_1[0x58] = param_1[0x58] | 0x2000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  sVar3 = param_1[0x23];
  if (sVar3 == 0x3de) {
    *(char *)((int)piVar4 + 0x11) =
         (char)*(undefined2 *)((int)&local_2c + (uint)*(byte *)((int)piVar4 + 0x11) * 2);
    *(undefined2 *)(piVar4 + 5) = 0x5f;
    *(undefined2 *)((int)piVar4 + 0x16) = 0x60;
  }
  else if ((sVar3 == 0x49f) || (sVar3 == 0x7be)) {
    *(char *)((int)piVar4 + 0x11) =
         (char)*(undefined2 *)((int)&local_38 + (uint)*(byte *)((int)piVar4 + 0x11) * 2);
    *(undefined2 *)(piVar4 + 5) = 0x48;
    *(undefined2 *)((int)piVar4 + 0x16) = 0x4a;
  }
  *(undefined2 *)(piVar4 + 8) = 0;
  uVar2 = FUN_800221a0(0,200);
  piVar4[7] = (int)(FLOAT_803e39e8 +
                   (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e39c8));
  piVar4[9] = *(int *)(param_1 + 6);
  if (param_1[0x23] == 0x7be) {
    *(undefined *)(piVar4 + 10) = 0;
  }
  else {
    *(undefined *)(piVar4 + 10) = 2;
  }
  return;
}

