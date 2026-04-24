// Function: FUN_8025a9ac
// Entry: 8025a9ac
// Size: 200 bytes

void FUN_8025a9ac(int param_1,ushort param_2,ushort param_3,int *param_4,int *param_5,
                 undefined4 *param_6)

{
  bool bVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  uVar4 = (uint)param_3;
  uVar3 = (uint)param_2;
  switch(param_1) {
  case 0:
  case 8:
  case 0xe:
  case 0x20:
  case 0x30:
    iVar5 = 3;
    iVar6 = 3;
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
    iVar5 = 3;
    iVar6 = 2;
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
    iVar5 = 2;
    iVar6 = 2;
    break;
  default:
    iVar6 = 0;
    iVar5 = 0;
  }
  if (param_2 == 0) {
    uVar3 = 1;
  }
  if (param_3 == 0) {
    uVar4 = 1;
  }
  bVar1 = true;
  *param_4 = (int)(uVar3 + (1 << iVar5) + -1) >> iVar5;
  *param_5 = (int)(uVar4 + (1 << iVar6) + -1) >> iVar6;
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

