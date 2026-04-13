// Function: FUN_80196794
// Entry: 80196794
// Size: 176 bytes

void FUN_80196794(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_800372f8(param_1,0x51);
  iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar1 == 0x49cb7) {
LAB_80196824:
    *(undefined2 *)(iVar2 + 0x4e) = 0x4b7;
  }
  else {
    if (iVar1 < 0x49cb7) {
      if (iVar1 == 0x49275) goto LAB_80196824;
      if (0x49274 < iVar1) {
        return;
      }
      if (iVar1 != 0x46406) {
        return;
      }
    }
    else {
      if (iVar1 == 0x4c797) goto LAB_80196824;
      if (0x4c796 < iVar1) {
        return;
      }
      if (iVar1 != 0x4bab1) {
        return;
      }
    }
    *(undefined2 *)(iVar2 + 0x4e) = 0x7d;
  }
  return;
}

