// Function: FUN_80245188
// Entry: 80245188
// Size: 92 bytes

undefined2 * FUN_80245188(void)

{
  undefined4 uVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_803ad3e0;
  uVar1 = FUN_8024377c();
  if (DAT_803ad428 == 0) {
    DAT_803ad428 = 1;
    DAT_803ad424 = uVar1;
  }
  else {
    FUN_802437a4();
    puVar2 = (undefined2 *)0x0;
  }
  return puVar2;
}

