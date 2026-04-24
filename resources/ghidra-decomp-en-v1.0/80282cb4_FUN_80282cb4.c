// Function: FUN_80282cb4
// Entry: 80282cb4
// Size: 112 bytes

uint FUN_80282cb4(uint param_1)

{
  switch(param_1 & 0xff) {
  case 0x80:
    return 0x80;
  case 0x81:
    return 0x82;
  case 0x82:
    return 0xa0;
  case 0x83:
    return 0xa1;
  case 0x84:
    return 0x83;
  case 0x85:
    return 0x84;
  case 0x86:
    return 0xa2;
  case 0x87:
    return 0xa3;
  case 0x88:
    return 0xa4;
  default:
    return param_1;
  }
}

