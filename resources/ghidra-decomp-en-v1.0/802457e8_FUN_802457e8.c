// Function: FUN_802457e8
// Entry: 802457e8
// Size: 112 bytes

byte FUN_802457e8(void)

{
  byte bVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  
  puVar3 = &DAT_803ad3e0;
  uVar2 = FUN_8024377c();
  if (DAT_803ad428 == 0) {
    DAT_803ad428 = 1;
    DAT_803ad424 = uVar2;
  }
  else {
    FUN_802437a4();
    puVar3 = (undefined2 *)0x0;
  }
  bVar1 = *(byte *)((int)puVar3 + 0x13);
  FUN_80245240(0,0);
  return bVar1 >> 7;
}

