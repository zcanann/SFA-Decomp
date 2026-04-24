// Function: FUN_802136dc
// Entry: 802136dc
// Size: 284 bytes

undefined4 FUN_802136dc(undefined4 param_1,int param_2)

{
  ushort uVar1;
  float fVar2;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,
                 (int)*(short *)(&DAT_803dc260 + (uint)*(byte *)(DAT_803ddd54 + 0xfd) * 2),0);
    *(undefined4 *)(param_2 + 0x2a0) =
         *(undefined4 *)(&DAT_8032a51c + (uint)*(byte *)(DAT_803ddd54 + 0xfd) * 4);
    fVar2 = FLOAT_803e67b8;
    *(float *)(param_2 + 0x280) = FLOAT_803e67b8;
    *(float *)(param_2 + 0x284) = fVar2;
  }
  uVar1 = *(ushort *)(&DAT_803dc288 + (uint)*(byte *)(DAT_803ddd54 + 0xfd) * 2);
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | (uint)uVar1;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 0x200) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffdff;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x800;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 0x400) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffbff;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x1000;
  }
  return 0;
}

