// Function: FUN_802460e4
// Entry: 802460e4
// Size: 172 bytes

void FUN_802460e4(int param_1,short param_2)

{
  undefined2 *puVar1;
  ulonglong uVar2;
  
  uVar2 = FUN_80243e74();
  if (DAT_803ae088 == 0) {
    puVar1 = &DAT_803ae054;
    DAT_803ae088 = 1;
    DAT_803ae084 = (int)(uVar2 >> 0x20);
  }
  else {
    FUN_80243e9c();
    puVar1 = (undefined2 *)0x0;
  }
  if (puVar1[param_1 + 0xe] == param_2) {
    FUN_80245938(0,0x14);
  }
  else {
    puVar1[param_1 + 0xe] = param_2;
    FUN_80245938(1,0x14);
  }
  return;
}

