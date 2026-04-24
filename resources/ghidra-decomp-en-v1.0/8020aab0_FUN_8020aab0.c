// Function: FUN_8020aab0
// Entry: 8020aab0
// Size: 664 bytes

void FUN_8020aab0(undefined4 param_1,int param_2,int param_3)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e6510;
  if (param_3 < 0x1a) {
    switch(param_3) {
    case 1:
      if ((*(byte *)(param_2 + 0x198) >> 6 & 1) == 0) {
        *(byte *)(param_2 + 0x198) = *(byte *)(param_2 + 0x198) & 0xbf | 0x40;
        if (*(int *)(param_2 + 0x160) != 0) {
          FUN_8001db6c((double)FLOAT_803e651c,*(int *)(param_2 + 0x160),1);
        }
      }
      else {
        *(undefined4 *)(param_2 + 0x168) = 0x12;
        if (*(int *)(param_2 + 0x160) != 0) {
          FUN_8001db6c((double)FLOAT_803e651c,*(int *)(param_2 + 0x160),0);
        }
      }
      break;
    case 2:
      FUN_8008016c(param_2 + 0x10);
      FUN_80080178(param_2 + 0x10,0x1e);
      *(undefined4 *)(param_2 + 0x174) = 2;
      *(float *)(param_2 + 0x14) = FLOAT_803e6510;
      break;
    case 3:
      FUN_8008016c(param_2 + 0x10);
      FUN_80080178(param_2 + 0x10,0x5a);
      *(float *)(param_2 + 0x14) = FLOAT_803e6540;
      *(undefined4 *)(param_2 + 0x174) = 1;
      *(undefined4 *)(param_2 + 0x184) = DAT_8032a014;
      *(undefined4 *)(param_2 + 0x188) = DAT_8032a020;
      break;
    case 4:
      FUN_8008016c(param_2 + 0x10);
      FUN_80080178(param_2 + 0x10,0x3c);
      *(float *)(param_2 + 0x14) = FLOAT_803e6544;
      *(undefined4 *)(param_2 + 0x174) = 1;
      *(undefined4 *)(param_2 + 0x184) = DAT_8032a018;
      *(undefined4 *)(param_2 + 0x188) = DAT_8032a024;
      break;
    case 5:
      FUN_8008016c(param_2 + 0x10);
      FUN_80080178(param_2 + 0x10,0x1e);
      *(float *)(param_2 + 0x14) = FLOAT_803e6548;
      *(undefined4 *)(param_2 + 0x174) = 1;
      *(undefined4 *)(param_2 + 0x184) = DAT_8032a01c;
      *(undefined4 *)(param_2 + 0x188) = DAT_8032a028;
      break;
    case 6:
      *(float *)(param_2 + 0x14) = FLOAT_803e6510;
      *(float *)(param_2 + 0x10) = fVar1;
      FUN_8008016c(param_2 + 0x10);
      break;
    case 7:
      *(undefined4 *)(param_2 + 0x168) = 0x13;
      *(float *)(param_2 + 0x164) = FLOAT_803e654c;
      *(byte *)(param_2 + 0x198) = *(byte *)(param_2 + 0x198) & 0xf7;
      break;
    case 8:
      *(undefined4 *)(param_2 + 0x168) = 0x11;
      break;
    case 9:
      *(undefined4 *)(param_2 + 0x168) = 0;
      break;
    case 10:
    case 0xb:
    case 0xc:
      if (*(int *)(param_2 + 0x170) < *(int *)(&DAT_8032a004 + param_3 * 4)) {
        *(undefined4 *)(param_2 + 0x194) = 1;
      }
      break;
    case 0xe:
    case 0xf:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
      *(char *)(param_2 + 400) = *(char *)(param_2 + 400) + '\x01';
      if (param_3 + -0xd < (int)(uint)*(byte *)(param_2 + 400)) {
        *(undefined *)(param_2 + 400) = 0;
        *(undefined4 *)(param_2 + 0x194) = 1;
      }
      break;
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
      iVar2 = FUN_8001ffb4((int)(short)((short)param_3 + 0xbe5));
      if (iVar2 != 0) {
        *(undefined4 *)(param_2 + 0x194) = 1;
      }
    case 0x18:
      iVar2 = FUN_80036e58(0x46,param_1,0);
      if (iVar2 != 0) {
        FUN_8021b358();
      }
      break;
    case 0x19:
      *(undefined4 *)(param_2 + 0x168) = 0x14;
      *(float *)(param_2 + 0x164) = FLOAT_803e654c;
    }
  }
  return;
}

