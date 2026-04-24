// Function: FUN_80245858
// Entry: 80245858
// Size: 164 bytes

void FUN_80245858(uint param_1)

{
  undefined4 uVar1;
  uint uVar2;
  undefined2 *puVar3;
  
  puVar3 = &DAT_803ad3e0;
  uVar2 = (param_1 & 1) << 7;
  uVar1 = FUN_8024377c();
  if (DAT_803ad428 == 0) {
    DAT_803ad428 = 1;
    DAT_803ad424 = uVar1;
  }
  else {
    FUN_802437a4();
    puVar3 = (undefined2 *)0x0;
  }
  if (uVar2 == (*(byte *)((int)puVar3 + 0x13) & 0x80)) {
    FUN_80245240(0,0);
  }
  else {
    *(byte *)((int)puVar3 + 0x13) = *(byte *)((int)puVar3 + 0x13) & 0x7f;
    *(byte *)((int)puVar3 + 0x13) = *(byte *)((int)puVar3 + 0x13) | (byte)uVar2;
    FUN_80245240(1,0);
  }
  return;
}

