// Function: FUN_8025a248
// Entry: 8025a248
// Size: 200 bytes

void FUN_8025a248(int param_1,ushort param_2,ushort param_3,int *param_4,int *param_5,
                 undefined4 *param_6)

{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  switch(param_1) {
  case 0:
  case 8:
  case 0xe:
  case 0x20:
  case 0x30:
    iVar3 = 3;
    iVar4 = 3;
    break;
  case 1:
  case 2:
  case 9:
  case 0x11:
  case 0x22:
  case 0x27:
  case 0x28:
  case 0x29:
  case 0x2a:
  case 0x39:
  case 0x3a:
    iVar3 = 3;
    iVar4 = 2;
    break;
  case 3:
  case 4:
  case 5:
  case 6:
  case 10:
  case 0x13:
  case 0x16:
  case 0x23:
  case 0x2b:
  case 0x2c:
  case 0x3c:
    iVar3 = 2;
    iVar4 = 2;
    break;
  default:
    iVar4 = 0;
    iVar3 = 0;
  }
  if (param_2 == 0) {
    param_2 = 1;
  }
  if (param_3 == 0) {
    param_3 = 1;
  }
  bVar1 = true;
  *param_4 = (int)((uint)param_2 + (1 << iVar3) + -1) >> iVar3;
  *param_5 = (int)((uint)param_3 + (1 << iVar4) + -1) >> iVar4;
  if ((param_1 != 6) && (param_1 != 0x16)) {
    bVar1 = false;
  }
  if (bVar1) {
    uVar2 = 2;
  }
  else {
    uVar2 = 1;
  }
  *param_6 = uVar2;
  return;
}

