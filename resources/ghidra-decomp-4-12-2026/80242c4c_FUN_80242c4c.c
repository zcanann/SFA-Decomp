// Function: FUN_80242c4c
// Entry: 80242c4c
// Size: 680 bytes

void FUN_80242c4c(int param_1)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined auStack_2e8 [416];
  undefined2 local_148;
  undefined2 local_146;
  
  FUN_8007d858();
  uVar2 = 0;
  do {
    FUN_8007d858();
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x10);
  FUN_8007d858();
  FUN_8007d858();
  FUN_8007d858();
  uVar2 = 0;
  do {
    FUN_8007d858();
    uVar2 = uVar2 + 1;
  } while (uVar2 < 4);
  if ((*(ushort *)(param_1 + 0x1a2) & 1) != 0) {
    FUN_80243e74();
    uVar2 = DAT_800000d4;
    local_148 = 0;
    local_146 = 0;
    if (auStack_2e8 == DAT_800000d8) {
      DAT_800000d8 = (undefined *)0x0;
    }
    FUN_802429a4((uint)auStack_2e8);
    FUN_8007d858();
    uVar3 = 0;
    iVar5 = param_1;
    do {
      FUN_80286718(*(double *)(iVar5 + 0x98));
      FUN_80286718(*(double *)(iVar5 + 0x90));
      FUN_8007d858();
      iVar5 = iVar5 + 0x10;
      uVar3 = uVar3 + 2;
    } while (uVar3 < 0x20);
    FUN_8007d858();
    uVar3 = 0;
    iVar5 = param_1;
    do {
      FUN_80286718(*(double *)(iVar5 + 0x1d0));
      FUN_80286718(*(double *)(iVar5 + 0x1c8));
      FUN_8007d858();
      iVar5 = iVar5 + 0x10;
      uVar3 = uVar3 + 2;
    } while (uVar3 < 0x20);
    local_148 = 0;
    local_146 = 0;
    if (auStack_2e8 == DAT_800000d8) {
      DAT_800000d8 = (undefined *)0x0;
    }
    FUN_802429a4(uVar2);
    FUN_80243e9c();
  }
  FUN_8007d858();
  puVar4 = *(undefined4 **)(param_1 + 4);
  uVar2 = 0;
  while (((puVar4 != (undefined4 *)0x0 && (puVar4 != (undefined4 *)0xffffffff)) &&
         (bVar1 = uVar2 < 0x10, uVar2 = uVar2 + 1, bVar1))) {
    FUN_8007d858();
    puVar4 = (undefined4 *)*puVar4;
  }
  return;
}

