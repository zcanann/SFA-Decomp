// Function: FUN_80213b9c
// Entry: 80213b9c
// Size: 432 bytes

undefined4 FUN_80213b9c(int param_1,int param_2)

{
  ushort uVar1;
  float fVar2;
  float fVar3;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,
                 (int)*(short *)(&DAT_803dc258 + (uint)*(byte *)(DAT_803ddd54 + 0xfc) * 2),0);
    fVar2 = FLOAT_803e67b8;
    *(float *)(param_2 + 0x280) = FLOAT_803e67b8;
    *(float *)(param_2 + 0x284) = fVar2;
  }
  uVar1 = *(ushort *)(&DAT_803dc268 + (uint)*(byte *)(DAT_803ddd54 + 0xfc) * 2);
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 4) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffb;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | (uint)uVar1;
  }
  uVar1 = *(ushort *)(&DAT_803dc270 + (uint)*(byte *)(DAT_803ddd54 + 0xfc) * 2);
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 2) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffd;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | (uint)uVar1;
  }
  if (*(char *)(DAT_803ddd54 + 0x108) == '\0') {
    uVar1 = *(ushort *)(&DAT_803dc280 + (uint)*(byte *)(DAT_803ddd54 + 0xfc) * 2);
  }
  else {
    uVar1 = *(ushort *)(&DAT_803dc278 + (uint)*(byte *)(DAT_803ddd54 + 0xfc) * 2);
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | (uint)uVar1;
  }
  fVar2 = FLOAT_803db418 * (*(float *)(DAT_803ddd54 + 0xe8) - *(float *)(param_1 + 0xc));
  fVar3 = FLOAT_803db418 * (*(float *)(DAT_803ddd54 + 0xf0) - *(float *)(param_1 + 0x14));
  FUN_802931a0((double)(fVar2 * fVar2 + fVar3 * fVar3));
  FUN_8002f5d4(param_1,param_2 + 0x2a0);
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(DAT_803ddd54 + 0xe8);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(DAT_803ddd54 + 0xf0);
  return 0;
}

