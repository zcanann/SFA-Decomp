// Function: FUN_801846d8
// Entry: 801846d8
// Size: 568 bytes

void FUN_801846d8(undefined2 *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  local_2c = DAT_802c2a00;
  local_28 = DAT_802c2a04;
  local_24 = DAT_802c2a08;
  local_38 = DAT_802c2a0c;
  local_34 = DAT_802c2a10;
  local_30 = DAT_802c2a14;
  piVar4 = *(int **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_8018405c;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)((int)piVar4 + 0xe) = *(undefined2 *)(param_2 + 0x1e);
  iVar2 = (int)*(short *)(param_2 + 0x1c);
  if (iVar2 == 0) {
    *piVar4 = 0;
  }
  else if (iVar2 == 0xff) {
    *piVar4 = -1;
  }
  else {
    *piVar4 = iVar2 * 0x3c;
  }
  uVar3 = FUN_80020078((int)*(short *)((int)piVar4 + 0xe));
  if (uVar3 != 0) {
    piVar4[1] = (int)FLOAT_803e4644;
    FUN_80035ff8((int)param_1);
  }
  *(undefined *)((int)piVar4 + 0x11) = *(undefined *)(param_2 + 0x19);
  DAT_803de748 = FUN_80013ee8(0x5b);
  uVar3 = FUN_80022264(0,100);
  *(short *)((int)piVar4 + 10) = (short)uVar3 + 300;
  *(undefined2 *)(piVar4 + 3) = 400;
  *(char *)((int)piVar4 + 0x12) = (char)*(undefined2 *)(param_2 + 0x1a);
  param_1[0x58] = param_1[0x58] | 0x2000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  sVar1 = param_1[0x23];
  if (sVar1 == 0x3de) {
    *(char *)((int)piVar4 + 0x11) =
         (char)*(undefined2 *)((int)&local_2c + (uint)*(byte *)((int)piVar4 + 0x11) * 2);
    *(undefined2 *)(piVar4 + 5) = 0x5f;
    *(undefined2 *)((int)piVar4 + 0x16) = 0x60;
  }
  else if ((sVar1 == 0x49f) || (sVar1 == 0x7be)) {
    *(char *)((int)piVar4 + 0x11) =
         (char)*(undefined2 *)((int)&local_38 + (uint)*(byte *)((int)piVar4 + 0x11) * 2);
    *(undefined2 *)(piVar4 + 5) = 0x48;
    *(undefined2 *)((int)piVar4 + 0x16) = 0x4a;
  }
  *(undefined2 *)(piVar4 + 8) = 0;
  uVar3 = FUN_80022264(0,200);
  piVar4[7] = (int)(FLOAT_803e4680 +
                   (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e4660));
  piVar4[9] = *(int *)(param_1 + 6);
  if (param_1[0x23] == 0x7be) {
    *(undefined *)(piVar4 + 10) = 0;
  }
  else {
    *(undefined *)(piVar4 + 10) = 2;
  }
  return;
}

