// Function: FUN_802c0978
// Entry: 802c0978
// Size: 228 bytes

undefined4 FUN_802c0978(int param_1,uint *param_2)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *param_2 = *param_2 | 0x200000;
  fVar2 = FLOAT_803e83a4;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    param_2[0xa5] = (uint)FLOAT_803e83a4;
    param_2[0xa1] = (uint)fVar2;
    param_2[0xa0] = (uint)fVar2;
    *(float *)(param_1 + 0x24) = fVar2;
    *(float *)(param_1 + 0x28) = fVar2;
    *(float *)(param_1 + 0x2c) = fVar2;
    *(undefined2 *)(param_2 + 0xce) = 0;
    param_2[0xa8] = (uint)FLOAT_803e83f4;
    param_2[0xae] = (uint)FLOAT_803e83f8;
    if (*(short *)(param_1 + 0xa0) != 0) {
      FUN_80030334(param_1,0,0);
    }
    bVar1 = *(byte *)(iVar3 + 0xbc0);
    if ((bVar1 >> 5 & 1) != 0) {
      *(byte *)(iVar3 + 0xbc0) = bVar1 & 0xdf;
      *(undefined *)((int)param_2 + 0x25f) = 0;
    }
  }
  if ((float)param_2[0xa6] < FLOAT_803e83bc) {
    *(undefined2 *)(param_2 + 0xcd) = 0;
    *(undefined2 *)((int)param_2 + 0x336) = 0;
    param_2[0xa6] = (uint)FLOAT_803e83a4;
  }
  return 0;
}

