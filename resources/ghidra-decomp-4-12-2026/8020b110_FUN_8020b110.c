// Function: FUN_8020b110
// Entry: 8020b110
// Size: 664 bytes

void FUN_8020b110(undefined4 param_1,int param_2,int param_3)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  fVar1 = FLOAT_803e71a8;
  if (param_3 < 0x1a) {
    switch(param_3) {
    case 1:
      if ((*(byte *)(param_2 + 0x198) >> 6 & 1) == 0) {
        *(byte *)(param_2 + 0x198) = *(byte *)(param_2 + 0x198) & 0xbf | 0x40;
        if (*(int *)(param_2 + 0x160) != 0) {
          FUN_8001dc30((double)FLOAT_803e71b4,*(int *)(param_2 + 0x160),'\x01');
        }
      }
      else {
        *(undefined4 *)(param_2 + 0x168) = 0x12;
        if (*(int *)(param_2 + 0x160) != 0) {
          FUN_8001dc30((double)FLOAT_803e71b4,*(int *)(param_2 + 0x160),'\0');
        }
      }
      break;
    case 2:
      FUN_800803f8((undefined4 *)(param_2 + 0x10));
      FUN_80080404((float *)(param_2 + 0x10),0x1e);
      *(undefined4 *)(param_2 + 0x174) = 2;
      *(float *)(param_2 + 0x14) = FLOAT_803e71a8;
      break;
    case 3:
      FUN_800803f8((undefined4 *)(param_2 + 0x10));
      FUN_80080404((float *)(param_2 + 0x10),0x5a);
      *(float *)(param_2 + 0x14) = FLOAT_803e71d8;
      *(undefined4 *)(param_2 + 0x174) = 1;
      *(undefined4 *)(param_2 + 0x184) = DAT_8032ac54;
      *(undefined4 *)(param_2 + 0x188) = DAT_8032ac60;
      break;
    case 4:
      FUN_800803f8((undefined4 *)(param_2 + 0x10));
      FUN_80080404((float *)(param_2 + 0x10),0x3c);
      *(float *)(param_2 + 0x14) = FLOAT_803e71dc;
      *(undefined4 *)(param_2 + 0x174) = 1;
      *(undefined4 *)(param_2 + 0x184) = DAT_8032ac58;
      *(undefined4 *)(param_2 + 0x188) = DAT_8032ac64;
      break;
    case 5:
      FUN_800803f8((undefined4 *)(param_2 + 0x10));
      FUN_80080404((float *)(param_2 + 0x10),0x1e);
      *(float *)(param_2 + 0x14) = FLOAT_803e71e0;
      *(undefined4 *)(param_2 + 0x174) = 1;
      *(undefined4 *)(param_2 + 0x184) = DAT_8032ac5c;
      *(undefined4 *)(param_2 + 0x188) = DAT_8032ac68;
      break;
    case 6:
      *(float *)(param_2 + 0x14) = FLOAT_803e71a8;
      *(float *)(param_2 + 0x10) = fVar1;
      FUN_800803f8((undefined4 *)(param_2 + 0x10));
      break;
    case 7:
      *(undefined4 *)(param_2 + 0x168) = 0x13;
      *(float *)(param_2 + 0x164) = FLOAT_803e71e4;
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
      if (*(int *)(param_2 + 0x170) < *(int *)(&DAT_8032ac44 + param_3 * 4)) {
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
      uVar2 = FUN_80020078((int)(short)((short)param_3 + 0xbe5));
      if (uVar2 != 0) {
        *(undefined4 *)(param_2 + 0x194) = 1;
      }
    case 0x18:
      iVar3 = FUN_80036f50(0x46,param_1,(float *)0x0);
      if (iVar3 != 0) {
        FUN_8021ba00(iVar3);
      }
      break;
    case 0x19:
      *(undefined4 *)(param_2 + 0x168) = 0x14;
      *(float *)(param_2 + 0x164) = FLOAT_803e71e4;
    }
  }
  return;
}

