// Function: FUN_8028383c
// Entry: 8028383c
// Size: 720 bytes

void FUN_8028383c(double param_1,double param_2,double param_3,int param_4,undefined4 param_5,
                 uint param_6,undefined4 param_7)

{
  uint uVar1;
  int iVar2;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  iVar2 = DAT_803de344 + param_4 * 0xf4;
  if ((double)FLOAT_803e78e0 <= param_1) {
    param_1 = (double)FLOAT_803e78e0;
  }
  if ((double)FLOAT_803e78e0 <= param_2) {
    param_2 = (double)FLOAT_803e78e0;
  }
  if ((double)FLOAT_803e78e0 <= param_3) {
    param_3 = (double)FLOAT_803e78e0;
  }
  uVar1 = countLeadingZeros(1 - (&DAT_803cc234)[(uint)*(byte *)(iVar2 + 0xef) * 0x2f]);
  FUN_8027f2ac(param_1,param_2,param_3,param_5,&local_44,param_6,param_7,
               (*(uint *)(iVar2 + 0xf0) & 0x80000000) != 0,uVar1 >> 5);
  local_40 = FLOAT_803e78e4 * local_40;
  local_3c = FLOAT_803e78e4 * local_3c;
  if ((((*(char *)(iVar2 + 0xe5) == -1) ||
       ((uint)*(ushort *)(iVar2 + 0x4c) != ((int)(FLOAT_803e78e4 * local_44) & 0xffffU))) ||
      ((uint)*(ushort *)(iVar2 + 0x4e) != ((int)local_40 & 0xffffU))) ||
     ((uint)*(ushort *)(iVar2 + 0x50) != ((int)local_3c & 0xffffU))) {
    *(short *)(iVar2 + 0x4c) = (short)(int)(FLOAT_803e78e4 * local_44);
    *(short *)(iVar2 + 0x4e) = (short)(int)local_40;
    *(short *)(iVar2 + 0x50) = (short)(int)local_3c;
    *(uint *)(iVar2 + 0x24) = *(uint *)(iVar2 + 0x24) | 1;
    *(undefined *)(iVar2 + 0xe5) = 0;
  }
  local_34 = FLOAT_803e78e4 * local_34;
  local_30 = FLOAT_803e78e4 * local_30;
  if (((*(char *)(iVar2 + 0xe6) == -1) ||
      ((uint)*(ushort *)(iVar2 + 0x52) != ((int)(FLOAT_803e78e4 * local_38) & 0xffffU))) ||
     (((uint)*(ushort *)(iVar2 + 0x54) != ((int)local_34 & 0xffffU) ||
      ((uint)*(ushort *)(iVar2 + 0x56) != ((int)local_30 & 0xffffU))))) {
    *(short *)(iVar2 + 0x52) = (short)(int)(FLOAT_803e78e4 * local_38);
    *(short *)(iVar2 + 0x54) = (short)(int)local_34;
    *(short *)(iVar2 + 0x56) = (short)(int)local_30;
    *(uint *)(iVar2 + 0x24) = *(uint *)(iVar2 + 0x24) | 2;
    *(undefined *)(iVar2 + 0xe6) = 0;
  }
  local_28 = FLOAT_803e78e4 * local_28;
  local_24 = FLOAT_803e78e4 * local_24;
  if (*(char *)(iVar2 + 0xe7) != -1) {
    if ((uint)*(ushort *)(iVar2 + 0x58) == ((int)(FLOAT_803e78e4 * local_2c) & 0xffffU)) {
      if ((uint)*(ushort *)(iVar2 + 0x5a) == ((int)local_28 & 0xffffU)) {
        if ((uint)*(ushort *)(iVar2 + 0x5c) == ((int)local_24 & 0xffffU)) goto LAB_80283ab8;
      }
    }
  }
  *(short *)(iVar2 + 0x58) = (short)(int)(FLOAT_803e78e4 * local_2c);
  *(short *)(iVar2 + 0x5a) = (short)(int)local_28;
  *(short *)(iVar2 + 0x5c) = (short)(int)local_24;
  *(uint *)(iVar2 + 0x24) = *(uint *)(iVar2 + 0x24) | 4;
  *(undefined *)(iVar2 + 0xe7) = 0;
LAB_80283ab8:
  if ((*(uint *)(iVar2 + 0xf0) & 0x80000000) != 0) {
    *(short *)(iVar2 + 0xd0) = *(short *)(&DAT_802c2820 + (param_6 >> 0xf & 0x1fe));
    *(short *)(iVar2 + 0xd2) = 0x20 - *(short *)(&DAT_802c2820 + (param_6 >> 0xf & 0x1fe));
    *(uint *)(iVar2 + 0x24) = *(uint *)(iVar2 + 0x24) | 0x200;
  }
  return;
}

