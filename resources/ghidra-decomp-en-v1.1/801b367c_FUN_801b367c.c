// Function: FUN_801b367c
// Entry: 801b367c
// Size: 628 bytes

void FUN_801b367c(undefined2 *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  undefined uVar5;
  
  FUN_80037a5c((int)param_1,4);
  if (param_1[0x23] == 0x1d6) {
    *(undefined4 *)(param_1 + 0x7a) = 0;
    iVar1 = *(int *)(param_1 + 0x32);
    if (iVar1 != 0) {
      *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xc10;
      *(uint *)(*(int *)(param_1 + 0x32) + 0x30) =
           *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 0x8000;
    }
    iVar1 = *(int *)(param_1 + 0x5c);
    uVar2 = FUN_80022264(0xffffff9c,100);
    *(char *)(iVar1 + 9) = (char)uVar2;
    uVar2 = FUN_80022264(0xffffff9c,100);
    *(char *)(iVar1 + 10) = (char)uVar2;
    uVar2 = FUN_80022264(0xffffff9c,100);
    *(char *)(iVar1 + 0xb) = (char)uVar2;
    *(undefined *)(iVar1 + 7) = 1;
    if (*(int *)(param_1 + 0x2a) != 0) {
      *(undefined2 *)(*(int *)(param_1 + 0x2a) + 0xb2) = 1;
    }
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x5c);
    if (*(char *)(param_1 + 0x56) == '\x13') {
      uVar5 = 0;
      uVar2 = FUN_80020078(0xc17);
      if ((uVar2 != 0) && (uVar2 = FUN_80020078(0xa21), uVar2 != 0)) {
        uVar5 = 1;
      }
      *(undefined *)(iVar1 + 0xb2) = uVar5;
    }
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 5) {
      iVar3 = iVar1 + (uint)bVar4 * 4;
      *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar3 + 0x3c) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar3 + 100) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar3 + 0x18) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar3 + 0x40) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar3 + 0x68) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar3 + 0x1c) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar3 + 0x44) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar3 + 0x6c) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar3 + 0x48) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar3 + 0x70) = *(undefined4 *)(param_1 + 10);
      *(undefined4 *)(iVar3 + 0x24) = *(undefined4 *)(param_1 + 6);
      *(undefined4 *)(iVar3 + 0x4c) = *(undefined4 *)(param_1 + 8);
      *(undefined4 *)(iVar3 + 0x74) = *(undefined4 *)(param_1 + 10);
    }
    *(undefined *)(iVar1 + 0xaf) = 0x80;
    *(float *)(iVar1 + 0x98) = FLOAT_803e5550;
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    *(code **)(param_1 + 0x5e) = FUN_801b2b04;
    *param_1 = (short)((int)*(char *)(param_2 + 0x28) << 8);
    DAT_803de7d0 = FUN_80013ee8(0x79);
    uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x1a));
    if (uVar2 != 0) {
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

