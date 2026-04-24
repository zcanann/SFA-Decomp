// Function: FUN_8007df10
// Entry: 8007df10
// Size: 668 bytes

void FUN_8007df10(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  if ((DAT_803dd059 != '\0') && ((DAT_803db700 == 7 || (DAT_803db700 == 9)))) {
    DAT_803db700 = 0xb;
  }
  switch(DAT_803db700) {
  case 0:
    *param_3 = 0;
    DAT_803db700 = 0xd;
    return;
  case 1:
    *param_1 = 1;
    param_1[1] = 2;
    *param_2 = 0x325;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    *param_3 = 2;
    return;
  case 2:
    *param_1 = 1;
    param_1[1] = 2;
    *param_2 = 0x51a;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    *param_3 = 2;
    return;
  case 3:
    *param_1 = 1;
    param_1[1] = 2;
    *param_2 = 0x51a;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    *param_3 = 2;
    return;
  case 4:
    *param_1 = 1;
    param_1[1] = 2;
    *param_2 = 0x329;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    *param_3 = 2;
    return;
  case 5:
    *param_1 = 1;
    param_1[1] = 2;
    param_1[2] = 0;
    *param_2 = 0x51f;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    param_2[3] = 0x326;
    *param_3 = 3;
    return;
  case 6:
    *param_1 = 1;
    param_1[1] = 2;
    param_1[2] = 0;
    *param_2 = 0x51e;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    param_2[3] = 0x326;
    *param_3 = 3;
    return;
  case 7:
    *param_1 = 1;
    param_1[1] = 2;
    *param_2 = 0x51c;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    *param_3 = 2;
    return;
  case 8:
    *param_3 = 0;
    return;
  case 9:
    *param_1 = 1;
    param_1[1] = 2;
    param_1[2] = 3;
    *param_2 = 0x32a;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    param_2[3] = 0x520;
    *param_3 = 3;
    return;
  case 10:
    *param_1 = 2;
    param_1[1] = 4;
    *param_2 = 0x497;
    param_2[1] = 0x51b;
    param_2[2] = 0x522;
    *param_3 = 2;
    return;
  case 0xb:
  case 0xc:
    *param_1 = 1;
    param_1[1] = 2;
    *param_2 = 0x521;
    param_2[1] = 0x51d;
    param_2[2] = 0x51b;
    *param_3 = 2;
    return;
  default:
    *param_3 = 0;
    DAT_803db700 = 0xd;
    return;
  }
}

