// Function: FUN_80227970
// Entry: 80227970
// Size: 88 bytes

undefined4 FUN_80227970(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  bVar1 = FUN_8001469c();
  if (bVar1 == 0) {
    *(undefined *)(iVar3 + 5) = 1;
    FUN_800201ac((int)*(short *)(iVar2 + 0x1e),1);
  }
  return 1;
}

