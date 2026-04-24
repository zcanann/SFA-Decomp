// Function: FUN_801ab900
// Entry: 801ab900
// Size: 176 bytes

void FUN_801ab900(int param_1)

{
  int iVar1;
  code **ppcVar2;
  
  ppcVar2 = *(code ***)(param_1 + 0xb8);
  if (*(byte *)((int)ppcVar2 + 6) != 0) {
    if ((*(byte *)((int)ppcVar2 + 6) & 1) == 0) {
      FUN_800200e8((int)*(short *)(ppcVar2 + 1),0);
    }
    else {
      FUN_800200e8((int)*(short *)(ppcVar2 + 1),1);
    }
    *(undefined *)((int)ppcVar2 + 6) = 0;
    iVar1 = FUN_8001ffb4(0xdf0);
    if ((iVar1 == 0) && (iVar1 = FUN_8001ffb4(0xaa), iVar1 != 0)) {
      FUN_800200e8(0xdf0,1);
    }
  }
  (**ppcVar2)(param_1,ppcVar2);
  return;
}

