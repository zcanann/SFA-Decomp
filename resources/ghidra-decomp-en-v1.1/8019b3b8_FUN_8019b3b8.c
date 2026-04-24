// Function: FUN_8019b3b8
// Entry: 8019b3b8
// Size: 272 bytes

void FUN_8019b3b8(undefined4 param_1,undefined4 param_2,ushort *param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < *(char *)((int)uVar4 + 0x1b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)((int)uVar4 + iVar3 + 0x13)) {
    case 0:
      if (param_3 != (ushort *)0x0) {
        FUN_8000bb38(uVar1,*param_3);
      }
      break;
    case 1:
      iVar2 = 1;
      break;
    case 2:
      iVar2 = 2;
      break;
    case 3:
      iVar2 = 3;
      break;
    case 4:
      iVar2 = 4;
      break;
    case 7:
      if (param_3 != (ushort *)0x0) {
        FUN_8000bb38(uVar1,param_3[1]);
      }
      break;
    case 9:
      FUN_8000bb38(uVar1,0xe1);
    }
  }
  if ((iVar2 != 0) && (param_3 != (ushort *)0x0)) {
    FUN_8000bb38(uVar1,param_3[2]);
  }
  FUN_8028688c();
  return;
}

