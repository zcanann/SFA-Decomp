// Function: FUN_8025831c
// Entry: 8025831c
// Size: 584 bytes

void FUN_8025831c(int param_1,undefined4 param_2,uint *param_3,uint *param_4,byte *param_5)

{
  uint *puVar1;
  int iVar2;
  uint *puVar3;
  uint *puVar4;
  
  iVar2 = DAT_803dd210 + param_1 * 4;
  puVar1 = (uint *)(iVar2 + 0x1c);
  puVar3 = (uint *)(iVar2 + 0x3c);
  puVar4 = (uint *)(iVar2 + 0x5c);
  switch(param_2) {
  case 9:
    *param_3 = *puVar1 & 1;
    *param_4 = *puVar1 >> 1 & 7;
    *param_5 = (byte)(*puVar1 >> 4) & 0x1f;
    return;
  case 10:
  case 0x19:
    break;
  case 0xb:
    *param_3 = *puVar1 >> 0xd & 1;
    *param_4 = *puVar1 >> 0xe & 7;
    *param_5 = 0;
    return;
  case 0xc:
    *param_3 = *puVar1 >> 0x11 & 1;
    *param_4 = *puVar1 >> 0x12 & 7;
    *param_5 = 0;
    return;
  case 0xd:
    *param_3 = *puVar1 >> 0x15 & 1;
    *param_4 = *puVar1 >> 0x16 & 7;
    *param_5 = (byte)(*puVar1 >> 0x19) & 0x1f;
    return;
  case 0xe:
    *param_3 = *puVar3 & 1;
    *param_4 = *puVar3 >> 1 & 7;
    *param_5 = (byte)(*puVar3 >> 4) & 0x1f;
    return;
  case 0xf:
    *param_3 = *puVar3 >> 9 & 1;
    *param_4 = *puVar3 >> 10 & 7;
    *param_5 = (byte)(*puVar3 >> 0xd) & 0x1f;
    return;
  case 0x10:
    *param_3 = *puVar3 >> 0x12 & 1;
    *param_4 = *puVar3 >> 0x13 & 7;
    *param_5 = (byte)(*puVar3 >> 0x16) & 0x1f;
    return;
  case 0x11:
    *param_3 = *puVar3 >> 0x1b & 1;
    *param_4 = *puVar3 >> 0x1c & 7;
    *param_5 = (byte)*puVar4 & 0x1f;
    return;
  case 0x12:
    *param_3 = *puVar4 >> 5 & 1;
    *param_4 = *puVar4 >> 6 & 7;
    *param_5 = (byte)(*puVar4 >> 9) & 0x1f;
    return;
  case 0x13:
    *param_3 = *puVar4 >> 0xe & 1;
    *param_4 = *puVar4 >> 0xf & 7;
    *param_5 = (byte)(*puVar4 >> 0x12) & 0x1f;
    return;
  case 0x14:
    *param_3 = *puVar4 >> 0x17 & 1;
    *param_4 = *puVar4 >> 0x18 & 7;
    *param_5 = (byte)(*puVar4 >> 0x1b);
    return;
  default:
    *param_3 = 1;
    *param_4 = 0;
    *param_5 = 0;
    return;
  }
  *param_3 = *puVar1 >> 9 & 1;
  if ((*param_3 == 1) && ((int)*puVar1 < 0)) {
    *param_3 = 2;
  }
  *param_4 = *puVar1 >> 10 & 7;
  *param_5 = 0;
  return;
}

