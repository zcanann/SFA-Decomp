// Function: FUN_80245ee0
// Entry: 80245ee0
// Size: 112 bytes

byte FUN_80245ee0(void)

{
  byte bVar1;
  undefined2 *puVar2;
  ulonglong uVar3;
  
  puVar2 = &DAT_803ae040;
  uVar3 = FUN_80243e74();
  if (DAT_803ae088 == 0) {
    DAT_803ae088 = 1;
    DAT_803ae084 = (int)(uVar3 >> 0x20);
  }
  else {
    FUN_80243e9c();
    puVar2 = (undefined2 *)0x0;
  }
  bVar1 = *(byte *)((int)puVar2 + 0x13);
  FUN_80245938(0,0);
  return bVar1 >> 7;
}

