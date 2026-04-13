// Function: FUN_80246060
// Entry: 80246060
// Size: 132 bytes

undefined2 FUN_80246060(int param_1)

{
  undefined2 uVar1;
  undefined2 *puVar2;
  ulonglong uVar3;
  
  uVar3 = FUN_80243e74();
  if (DAT_803ae088 == 0) {
    puVar2 = &DAT_803ae054;
    DAT_803ae088 = 1;
    DAT_803ae084 = (int)(uVar3 >> 0x20);
  }
  else {
    FUN_80243e9c();
    puVar2 = (undefined2 *)0x0;
  }
  uVar1 = puVar2[param_1 + 0xe];
  FUN_80245938(0,0x14);
  return uVar1;
}

