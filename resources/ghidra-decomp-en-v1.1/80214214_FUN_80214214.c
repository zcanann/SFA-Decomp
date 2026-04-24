// Function: FUN_80214214
// Entry: 80214214
// Size: 432 bytes

undefined4
FUN_80214214(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  ushort uVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e7450,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(&DAT_803dcec0 + (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 2),0
                 ,param_12,param_13,param_14,param_15,param_16);
    fVar2 = FLOAT_803e7450;
    *(float *)(param_10 + 0x280) = FLOAT_803e7450;
    *(float *)(param_10 + 0x284) = fVar2;
  }
  uVar1 = *(ushort *)(&DAT_803dced0 + (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 2);
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 4) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffb;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | (uint)uVar1;
  }
  uVar1 = *(ushort *)(&DAT_803dced8 + (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 2);
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 2) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffd;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | (uint)uVar1;
  }
  if (*(char *)(DAT_803de9d4 + 0x108) == '\0') {
    uVar1 = *(ushort *)(&DAT_803dcee8 + (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 2);
  }
  else {
    uVar1 = *(ushort *)(&DAT_803dcee0 + (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 2);
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | (uint)uVar1;
  }
  fVar2 = FLOAT_803dc078 * (*(float *)(DAT_803de9d4 + 0xe8) - *(float *)(param_9 + 0xc));
  fVar3 = FLOAT_803dc078 * (*(float *)(DAT_803de9d4 + 0xf0) - *(float *)(param_9 + 0x14));
  dVar4 = FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
  FUN_8002f6cc(dVar4,param_9,(float *)(param_10 + 0x2a0));
  *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(DAT_803de9d4 + 0xe8);
  *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(DAT_803de9d4 + 0xf0);
  return 0;
}

