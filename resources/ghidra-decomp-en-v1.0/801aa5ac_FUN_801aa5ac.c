// Function: FUN_801aa5ac
// Entry: 801aa5ac
// Size: 232 bytes

void FUN_801aa5ac(int param_1)

{
  int iVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4(0x1c2);
  if ((iVar1 == 0) && (iVar1 = FUN_8001ffb4(0xa3), iVar1 != 0)) {
    iVar1 = FUN_8002b9ec();
    dVar3 = (double)FUN_800216d0(param_1 + 0x18,iVar1 + 0x18);
    if (dVar3 < (double)FLOAT_803e4664) {
      FUN_800200e8(0x1c2,1);
    }
  }
  iVar1 = FUN_8001ffb4(0x1c3);
  if (iVar1 == 0) {
    FUN_8002fa48((double)FLOAT_803e4668,(double)FLOAT_803db414,param_1,0);
    FUN_80115094(param_1,iVar2);
    FUN_8003b310(param_1,iVar2 + 0x624);
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    FUN_80035f00(param_1);
  }
  return;
}

