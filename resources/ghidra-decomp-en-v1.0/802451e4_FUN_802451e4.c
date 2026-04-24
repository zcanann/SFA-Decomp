// Function: FUN_802451e4
// Entry: 802451e4
// Size: 92 bytes

undefined2 * FUN_802451e4(void)

{
  undefined4 uVar1;
  undefined2 *puVar2;
  
  uVar1 = FUN_8024377c();
  if (DAT_803ad428 == 0) {
    puVar2 = &DAT_803ad3f4;
    DAT_803ad428 = 1;
    DAT_803ad424 = uVar1;
  }
  else {
    FUN_802437a4();
    puVar2 = (undefined2 *)0x0;
  }
  return puVar2;
}

