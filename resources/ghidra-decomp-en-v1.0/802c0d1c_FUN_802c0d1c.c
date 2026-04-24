// Function: FUN_802c0d1c
// Entry: 802c0d1c
// Size: 148 bytes

void FUN_802c0d1c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar1 + 0xbb2) = (char)param_2;
  if (param_2 == 1) {
    *(undefined *)(iVar1 + 0x464) = 0;
    if (*(short *)(param_1 + 0xb4) != -1) {
      (**(code **)(*DAT_803dca54 + 0x4c))();
    }
  }
  else {
    *(undefined *)(iVar1 + 0x464) = 1;
  }
  if (param_2 == 2) {
    FUN_800200e8(0xed7,1);
  }
  else {
    FUN_800200e8(0xed7,0);
  }
  return;
}

