// Function: FUN_80245a68
// Entry: 80245a68
// Size: 204 bytes

void FUN_80245a68(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  
  if (*(int *)(param_1 + 0x30) != 0) {
    uVar4 = FUN_80246c50();
    uVar3 = (uint)uVar4 - *(uint *)(param_1 + 0x2c);
    uVar1 = *(uint *)(param_1 + 0xc);
    uVar2 = (int)((ulonglong)uVar4 >> 0x20) -
            ((uint)((uint)uVar4 < *(uint *)(param_1 + 0x2c)) + *(int *)(param_1 + 0x28));
    *(uint *)(param_1 + 0xc) = uVar1 + uVar3;
    *(uint *)(param_1 + 8) = *(int *)(param_1 + 8) + uVar2 + CARRY4(uVar1,uVar3);
    *(undefined4 *)(param_1 + 0x30) = 0;
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + 1;
    if ((*(uint *)(param_1 + 0x20) ^ 0x80000000) <
        (uint)(*(uint *)(param_1 + 0x24) < uVar3) + (uVar2 ^ 0x80000000)) {
      *(uint *)(param_1 + 0x24) = uVar3;
      *(uint *)(param_1 + 0x20) = uVar2;
    }
    if ((uVar2 ^ 0x80000000) <
        (uint)(uVar3 < *(uint *)(param_1 + 0x1c)) + (*(uint *)(param_1 + 0x18) ^ 0x80000000)) {
      *(uint *)(param_1 + 0x1c) = uVar3;
      *(uint *)(param_1 + 0x18) = uVar2;
    }
  }
  return;
}

