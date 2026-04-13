// Function: FUN_80234710
// Entry: 80234710
// Size: 892 bytes

void FUN_80234710(short *param_1,char *param_2)

{
  uint uVar1;
  
  uVar1 = FUN_80014e9c(0);
  if ((uVar1 & 0x10) != 0) {
    param_2[0xc] = param_2[0xc] ^ 1;
  }
  if (param_2[0xc] != '\0') {
    if ((uVar1 & 8) != 0) {
      param_2[0xd] = param_2[0xd] + '\x01';
    }
    if ((uVar1 & 4) != 0) {
      param_2[0xd] = param_2[0xd] + -1;
    }
    if ('\a' < param_2[0xd]) {
      param_2[0xd] = '\0';
    }
    if (param_2[0xd] < '\0') {
      param_2[0xd] = '\a';
    }
    switch(param_2[0xd]) {
    case '\0':
      if ((uVar1 & 1) != 0) {
        *param_1 = *param_1 + -1000;
      }
      if ((uVar1 & 2) != 0) {
        *param_1 = *param_1 + 1000;
      }
      FUN_80137cd0();
      FUN_80137cd0();
      break;
    case '\x01':
      if ((uVar1 & 1) != 0) {
        param_1[1] = param_1[1] + -1000;
      }
      if ((uVar1 & 2) != 0) {
        param_1[1] = param_1[1] + 1000;
      }
      FUN_80137cd0();
      FUN_80137cd0();
      break;
    case '\x02':
      if ((uVar1 & 1) != 0) {
        *param_2 = *param_2 + -5;
      }
      if ((uVar1 & 2) != 0) {
        *param_2 = *param_2 + '\x05';
      }
      FUN_80137cd0();
      FUN_80137cd0();
      break;
    case '\x03':
      if ((uVar1 & 1) != 0) {
        param_2[1] = param_2[1] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[1] = param_2[1] + '\x05';
      }
      FUN_80137cd0();
      FUN_80137cd0();
      break;
    case '\x04':
      if ((uVar1 & 1) != 0) {
        param_2[2] = param_2[2] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[2] = param_2[2] + '\x05';
      }
      FUN_80137cd0();
      FUN_80137cd0();
      break;
    case '\x05':
      if ((uVar1 & 1) != 0) {
        param_2[4] = param_2[4] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[4] = param_2[4] + '\x05';
      }
      FUN_80137cd0();
      FUN_80137cd0();
      break;
    case '\x06':
      if ((uVar1 & 1) != 0) {
        param_2[5] = param_2[5] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[5] = param_2[5] + '\x05';
      }
      FUN_80137cd0();
      FUN_80137cd0();
      break;
    case '\a':
      if ((uVar1 & 1) != 0) {
        param_2[6] = param_2[6] + -5;
      }
      if ((uVar1 & 2) != 0) {
        param_2[6] = param_2[6] + '\x05';
      }
      FUN_80137cd0();
      FUN_80137cd0();
    }
  }
  return;
}

