// Function: FUN_802272c8
// Entry: 802272c8
// Size: 88 bytes

undefined4 FUN_802272c8(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_80014670();
  if (iVar1 == 0) {
    *(undefined *)(iVar3 + 5) = 1;
    FUN_800200e8((int)*(short *)(iVar2 + 0x1e),1);
  }
  return 1;
}

