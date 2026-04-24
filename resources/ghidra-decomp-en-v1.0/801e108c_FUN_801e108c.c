// Function: FUN_801e108c
// Entry: 801e108c
// Size: 592 bytes

void FUN_801e108c(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar1 = FUN_8002b9ec();
  iVar2 = FUN_8001ffb4(0xa3c);
  if (iVar2 != 0) {
    uVar3 = FUN_8002e0b4(0x467e8);
    FUN_80008cbc(uVar3,uVar1,*(undefined *)(param_1 + (uint)*(byte *)(param_1 + 0xa4) + 0xa9),0);
    uVar3 = FUN_8002e0b4(0x467e7);
    FUN_80008cbc(uVar3,uVar1,*(undefined *)(param_1 + (*(byte *)(param_1 + 0xa4) ^ 1) + 0xa7),0);
    FUN_80008cbc(uVar1,uVar1,0x96,0);
    FUN_800200e8(0xa3c,0);
    *(undefined2 *)(param_1 + 0xa2) = 0xa3e;
  }
  iVar2 = FUN_8001ffb4(0xa3d);
  if (iVar2 != 0) {
    uVar3 = FUN_8002e0b4(0x467e7);
    FUN_80008cbc(uVar3,uVar1,*(undefined *)(param_1 + (uint)*(byte *)(param_1 + 0xa4) + 0xa9),0);
    uVar3 = FUN_8002e0b4(0x467e8);
    FUN_80008cbc(uVar3,uVar1,*(undefined *)(param_1 + (*(byte *)(param_1 + 0xa4) ^ 1) + 0xa7),0);
    FUN_80008cbc(uVar1,uVar1,0x96,0);
    FUN_800200e8(0xa3d,0);
    *(undefined2 *)(param_1 + 0xa2) = 0xa3f;
  }
  iVar2 = FUN_8001ffb4(0xa3e);
  if (iVar2 != 0) {
    if (*(short *)(param_1 + 0xa2) != 0xa3e) {
      *(byte *)(param_1 + 0xa4) = *(byte *)(param_1 + 0xa4) ^ 1;
    }
    FUN_80008cbc(uVar1,uVar1,*(undefined *)(param_1 + (*(byte *)(param_1 + 0xa4) ^ 1) + 0xa5),0);
    FUN_80008cbc(uVar1,uVar1,*(undefined *)(param_1 + (uint)*(byte *)(param_1 + 0xa4) + 0xa9),0);
    FUN_80008cbc(uVar1,uVar1,0x8a,0);
    FUN_800200e8(0xa3e,0);
  }
  iVar2 = FUN_8001ffb4(0xa3f);
  if (iVar2 != 0) {
    if (*(short *)(param_1 + 0xa2) != 0xa3f) {
      *(byte *)(param_1 + 0xa4) = *(byte *)(param_1 + 0xa4) ^ 1;
    }
    FUN_80008cbc(uVar1,uVar1,*(undefined *)(param_1 + (*(byte *)(param_1 + 0xa4) ^ 1) + 0xa5),0);
    FUN_80008cbc(uVar1,uVar1,*(undefined *)(param_1 + (uint)*(byte *)(param_1 + 0xa4) + 0xa9),0);
    FUN_80008cbc(uVar1,uVar1,0x8a,0);
    FUN_800200e8(0xa3f,0);
  }
  return;
}

