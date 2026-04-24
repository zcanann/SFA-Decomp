// Function: FUN_802b4de0
// Entry: 802b4de0
// Size: 248 bytes

void FUN_802b4de0(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (DAT_803de448 != 0) {
    FUN_8002cbc4();
    FUN_80037cb0(param_1,DAT_803de448);
    DAT_803de448 = 0;
  }
  if (DAT_803de44c != 0) {
    FUN_8002cbc4();
    FUN_80037cb0(param_1,DAT_803de44c);
    DAT_803de44c = 0;
  }
  if (DAT_803de450 != 0) {
    DAT_803de450 = 0;
  }
  iVar3 = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar1 + 0x8a8); iVar2 = iVar2 + 1) {
    if (*(int *)(*(int *)(iVar1 + 0x3dc) + iVar3 + 100) != 0) {
      FUN_80023800();
    }
    iVar3 = iVar3 + 0xb0;
  }
  FUN_80036fa4(param_1,0);
  FUN_80036fa4(param_1,0x25);
  FUN_80026c88(DAT_803de420);
  return;
}

