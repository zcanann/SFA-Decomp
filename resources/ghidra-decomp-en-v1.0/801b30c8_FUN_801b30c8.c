// Function: FUN_801b30c8
// Entry: 801b30c8
// Size: 628 bytes

void FUN_801b30c8(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined uVar3;
  int iVar2;
  byte bVar4;
  
  FUN_80037964(param_1,4);
  if (param_1[0x23] == 0x1d6) {
    *(undefined4 *)(param_1 + 0x7a) = 0;
    iVar1 = *(int *)(param_1 + 0x32);
    if (iVar1 != 0) {
      *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xc10;
      *(uint *)(*(int *)(param_1 + 0x32) + 0x30) =
           *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 0x8000;
    }
    iVar1 = *(int *)(param_1 + 0x5c);
    uVar3 = FUN_800221a0(0xffffff9c,100);
    *(undefined *)(iVar1 + 9) = uVar3;
    uVar3 = FUN_800221a0(0xffffff9c,100);
    *(undefined *)(iVar1 + 10) = uVar3;
    uVar3 = FUN_800221a0(0xffffff9c,100);
    *(undefined *)(iVar1 + 0xb) = uVar3;
    *(undefined *)(iVar1 + 7) = 1;
    if (*(int *)(param_1 + 0x2a) != 0) {
      *(undefined2 *)(*(int *)(param_1 + 0x2a) + 0xb2) = 1;
    }
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x5c);
    if (*(char *)(param_1 + 0x56) == '\x13') {
      uVar3 = 0;
      iVar2 = FUN_8001ffb4(0xc17);
      if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0xa21), iVar2 != 0)) {
        uVar3 = 1;
      }
      *(undefined *)(iVar1 + 0xb2) = uVar3;
    }
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 5) {
      iVar2 = iVar1 + (uint)bVar4 * 4;
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar2 + 0x3c) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar2 + 100) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar2 + 0x18) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar2 + 0x40) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar2 + 0x68) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar2 + 0x1c) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar2 + 0x44) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar2 + 0x6c) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar2 + 0x20) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar2 + 0x48) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar2 + 0x70) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar2 + 0x24) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar2 + 0x4c) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar2 + 0x74) = *(undefined4 *)(param_1 + 10);
    }
    *(undefined *)(iVar1 + 0xaf) = 0x80;
    *(float *)(iVar1 + 0x98) = FLOAT_803e48b8;
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    *(code **)(param_1 + 0x5e) = FUN_801b2550;
    *param_1 = (short)((int)*(char *)(param_2 + 0x28) << 8);
    DAT_803ddb50 = FUN_80013ec8(0x79,1);
    iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1a));
    if (iVar2 != 0) {
      *(undefined *)(iVar1 + 0xb0) = 0x3c;
      *(undefined *)(iVar1 + 0xac) = 5;
    }
    *(undefined4 *)(iVar1 + 0x8c) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(iVar1 + 0x90) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(iVar1 + 0x94) = *(undefined4 *)(param_1 + 10);
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

