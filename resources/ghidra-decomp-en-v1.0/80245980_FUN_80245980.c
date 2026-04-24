// Function: FUN_80245980
// Entry: 80245980
// Size: 172 bytes

void FUN_80245980(int param_1,short param_2)

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
  if (puVar2[param_1 + 0xe] == param_2) {
    FUN_80245240(0,0x14);
  }
  else {
    puVar2[param_1 + 0xe] = param_2;
    FUN_80245240(1,0x14);
  }
  return;
}

