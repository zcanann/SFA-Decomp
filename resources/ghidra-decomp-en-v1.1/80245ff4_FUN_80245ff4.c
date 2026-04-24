// Function: FUN_80245ff4
// Entry: 80245ff4
// Size: 108 bytes

undefined FUN_80245ff4(void)

{
  undefined uVar1;
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
  uVar1 = *(undefined *)(puVar2 + 9);
  FUN_80245938(0,0);
  return uVar1;
}

