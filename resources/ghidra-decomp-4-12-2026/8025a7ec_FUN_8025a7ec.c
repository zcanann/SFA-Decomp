// Function: FUN_8025a7ec
// Entry: 8025a7ec
// Size: 100 bytes

void FUN_8025a7ec(undefined4 param_1,undefined4 *param_2,undefined4 *param_3)

{
  switch(param_1) {
  case 0:
  case 8:
  case 0xe:
  case 0x20:
  case 0x30:
    *param_2 = 3;
    *param_3 = 3;
    return;
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
    *param_2 = 3;
    *param_3 = 2;
    return;
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
    *param_2 = 2;
    *param_3 = 2;
    return;
  default:
    *param_3 = 0;
    *param_2 = 0;
    return;
  }
}

