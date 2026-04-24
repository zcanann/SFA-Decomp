// Function: FUN_80219790
// Entry: 80219790
// Size: 268 bytes

void FUN_80219790(undefined4 param_1,undefined4 param_2,ushort *param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  uVar2 = 0;
  for (iVar3 = 0; iVar3 < *(char *)((int)uVar4 + 0x1b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)((int)uVar4 + iVar3 + 0x13)) {
    case 0:
      if (param_3 != (ushort *)0x0) {
        FUN_8000bb38(uVar1,*param_3);
      }
      break;
    case 1:
      uVar2 = uVar2 | 1;
      break;
    case 2:
      uVar2 = uVar2 | 2;
      break;
    case 3:
      uVar2 = uVar2 | 4;
      break;
    case 4:
      uVar2 = uVar2 | 8;
      break;
    case 7:
      if (param_3 != (ushort *)0x0) {
        FUN_8000bb38(uVar1,param_3[1]);
      }
    }
  }
  if ((uVar2 != 0) && (param_3 != (ushort *)0x0)) {
    FUN_8000bb38(uVar1,param_3[3]);
  }
  FUN_8028688c();
  return;
}

