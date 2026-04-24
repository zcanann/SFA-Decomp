// Function: FUN_8019ae3c
// Entry: 8019ae3c
// Size: 272 bytes

void FUN_8019ae3c(undefined4 param_1,undefined4 param_2,undefined2 *param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < *(char *)((int)uVar4 + 0x1b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)((int)uVar4 + iVar3 + 0x13)) {
    case 0:
      if (param_3 != (undefined2 *)0x0) {
        FUN_8000bb18(uVar1,*param_3);
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
      if (param_3 != (undefined2 *)0x0) {
        FUN_8000bb18(uVar1,param_3[1]);
      }
      break;
    case 9:
      FUN_8000bb18(uVar1,0xe1);
    }
  }
  if ((iVar2 != 0) && (param_3 != (undefined2 *)0x0)) {
    FUN_8000bb18(uVar1,param_3[2]);
  }
  FUN_80286128(iVar2);
  return;
}

