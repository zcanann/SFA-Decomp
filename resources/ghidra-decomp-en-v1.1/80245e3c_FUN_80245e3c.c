// Function: FUN_80245e3c
// Entry: 80245e3c
// Size: 164 bytes

void FUN_80245e3c(uint param_1)

{
  uint uVar1;
  undefined2 *puVar2;
  ulonglong uVar3;
  
  puVar2 = &DAT_803ae040;
  uVar1 = (param_1 & 1) << 2;
  uVar3 = FUN_80243e74();
  if (DAT_803ae088 == 0) {
    DAT_803ae088 = 1;
    DAT_803ae084 = (int)(uVar3 >> 0x20);
  }
  else {
    FUN_80243e9c();
    puVar2 = (undefined2 *)0x0;
  }
  if (uVar1 == (*(byte *)((int)puVar2 + 0x13) & 4)) {
    FUN_80245938(0,0);
  }
  else {
    *(byte *)((int)puVar2 + 0x13) = *(byte *)((int)puVar2 + 0x13) & 0xfb;
    *(byte *)((int)puVar2 + 0x13) = *(byte *)((int)puVar2 + 0x13) | (byte)uVar1;
    FUN_80245938(1,0);
  }
  return;
}

