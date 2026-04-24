// Function: FUN_8025a0ec
// Entry: 8025a0ec
// Size: 348 bytes

int FUN_8025a0ec(uint param_1,uint param_2,int param_3,char param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  switch(param_3) {
  case 0:
  case 8:
  case 0xe:
  case 0x20:
  case 0x30:
    iVar3 = 3;
    iVar5 = 3;
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
    iVar5 = 2;
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
    iVar5 = 2;
    break;
  default:
    iVar5 = 0;
    iVar3 = 0;
  }
  if ((param_3 == 6) || (param_3 == 0x16)) {
    iVar4 = 0x40;
  }
  else {
    iVar4 = 0x20;
  }
  if (param_4 == '\x01') {
    iVar6 = 0;
    for (param_5 = param_5 & 0xff; param_5 != 0; param_5 = param_5 - 1) {
      uVar1 = param_1 & 0xffff;
      uVar2 = param_2 & 0xffff;
      iVar6 = iVar6 + iVar4 * ((int)(uVar1 + (1 << iVar3) + -1) >> iVar3) *
                              ((int)(uVar2 + (1 << iVar5) + -1) >> iVar5);
      if ((uVar1 == 1) && (uVar2 == 1)) {
        return iVar6;
      }
      if ((param_1 & 0xffff) < 2) {
        param_1 = 1;
      }
      else {
        param_1 = (int)uVar1 >> 1;
      }
      if ((param_2 & 0xffff) < 2) {
        param_2 = 1;
      }
      else {
        param_2 = (int)uVar2 >> 1;
      }
    }
  }
  else {
    iVar6 = iVar4 * ((int)((param_1 & 0xffff) + (1 << iVar3) + -1) >> iVar3) *
                    ((int)((param_2 & 0xffff) + (1 << iVar5) + -1) >> iVar5);
  }
  return iVar6;
}

