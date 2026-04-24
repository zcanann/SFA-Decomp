// Function: FUN_802b5540
// Entry: 802b5540
// Size: 248 bytes

void FUN_802b5540(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 in_f1;
  undefined8 in_f2;
  undefined8 in_f3;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (DAT_803df0c8 != 0) {
    FUN_8002cc9c(in_f1,in_f2,in_f3,in_f4,in_f5,in_f6,in_f7,in_f8,DAT_803df0c8);
    in_f1 = FUN_80037da8(param_1,DAT_803df0c8);
    DAT_803df0c8 = 0;
  }
  if (DAT_803df0cc != 0) {
    FUN_8002cc9c(in_f1,in_f2,in_f3,in_f4,in_f5,in_f6,in_f7,in_f8,DAT_803df0cc);
    FUN_80037da8(param_1,DAT_803df0cc);
    DAT_803df0cc = 0;
  }
  if (DAT_803df0d0 != 0) {
    DAT_803df0d0 = 0;
  }
  iVar4 = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar2 + 0x8a8); iVar3 = iVar3 + 1) {
    uVar1 = *(uint *)(*(int *)(iVar2 + 0x3dc) + iVar4 + 100);
    if (uVar1 != 0) {
      FUN_800238c4(uVar1);
    }
    iVar4 = iVar4 + 0xb0;
  }
  FUN_8003709c(param_1,0);
  FUN_8003709c(param_1,0x25);
  FUN_80026d4c(DAT_803df0a0);
  return;
}

