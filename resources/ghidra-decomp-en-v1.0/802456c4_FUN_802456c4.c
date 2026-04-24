// Function: FUN_802456c4
// Entry: 802456c4
// Size: 128 bytes

bool FUN_802456c4(void)

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
  return (bVar1 & 4) != 0;
}

