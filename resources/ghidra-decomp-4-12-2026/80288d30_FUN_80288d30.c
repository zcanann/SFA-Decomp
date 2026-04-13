// Function: FUN_80288d30
// Entry: 80288d30
// Size: 340 bytes

void FUN_80288d30(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  
  iVar1 = FUN_8028be24();
  if (iVar1 == 0) {
    FUN_80287e5c(param_1,'\x01');
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x80;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x16;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar1 = 3;
    do {
      iVar3 = FUN_80287460(param_1);
      iVar1 = iVar1 + -1;
      if (iVar3 == 0) {
        return;
      }
    } while (0 < iVar1);
  }
  else {
    FUN_80287e5c(param_1,'\x01');
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x80;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar1 = 3;
    do {
      uVar4 = FUN_80287460(param_1);
      iVar3 = (int)((ulonglong)uVar4 >> 0x20);
      iVar1 = iVar1 + -1;
      if (iVar3 == 0) break;
    } while (0 < iVar1);
    if (iVar3 == 0) {
      FUN_8028da78(0,(int)uVar4,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  return;
}

