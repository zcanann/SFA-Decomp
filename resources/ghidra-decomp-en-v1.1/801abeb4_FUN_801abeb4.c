// Function: FUN_801abeb4
// Entry: 801abeb4
// Size: 176 bytes

void FUN_801abeb4(int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0xb8);
  if (*(byte *)((int)puVar2 + 6) != 0) {
    if ((*(byte *)((int)puVar2 + 6) & 1) == 0) {
      FUN_800201ac((int)*(short *)(puVar2 + 1),0);
    }
    else {
      FUN_800201ac((int)*(short *)(puVar2 + 1),1);
    }
    *(undefined *)((int)puVar2 + 6) = 0;
    uVar1 = FUN_80020078(0xdf0);
    if ((uVar1 == 0) && (uVar1 = FUN_80020078(0xaa), uVar1 != 0)) {
      FUN_800201ac(0xdf0,1);
    }
  }
  (*(code *)*puVar2)(param_1,puVar2);
  return;
}

