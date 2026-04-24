// Function: FUN_802458fc
// Entry: 802458fc
// Size: 132 bytes

undefined2 FUN_802458fc(int param_1)

{
  undefined2 uVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  
  uVar2 = FUN_8024377c();
  if (DAT_803ad428 == 0) {
    puVar3 = &DAT_803ad3f4;
    DAT_803ad428 = 1;
    DAT_803ad424 = uVar2;
  }
  else {
    FUN_802437a4();
    puVar3 = (undefined2 *)0x0;
  }
  uVar1 = puVar3[param_1 + 0xe];
  FUN_80245240(0,0x14);
  return uVar1;
}

