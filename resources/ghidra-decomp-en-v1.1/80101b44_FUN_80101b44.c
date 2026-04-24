// Function: FUN_80101b44
// Entry: 80101b44
// Size: 204 bytes

void FUN_80101b44(uint param_1,undefined param_2)

{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  
  FUN_8000facc();
  fVar1 = FLOAT_803e22ac;
  *(float *)(DAT_803de19c + 0xf4) = FLOAT_803e22ac;
  *(float *)(DAT_803de19c + 0xf8) =
       fVar1 / (float)((double)CONCAT44(0x43300000,param_1 & 0xff) - DOUBLE_803e22e0);
  *(undefined *)(DAT_803de19c + 0x13f) = param_2;
  puVar2 = FUN_8000facc();
  *(undefined4 *)(DAT_803de19c + 0x10c) = *(undefined4 *)(puVar2 + 6);
  *(undefined4 *)(DAT_803de19c + 0x110) = *(undefined4 *)(puVar2 + 8);
  *(undefined4 *)(DAT_803de19c + 0x114) = *(undefined4 *)(puVar2 + 10);
  *(undefined2 *)(DAT_803de19c + 0x106) = *puVar2;
  *(undefined2 *)(DAT_803de19c + 0x108) = puVar2[1];
  *(undefined2 *)(DAT_803de19c + 0x10a) = puVar2[2];
  dVar3 = FUN_8000fc54();
  *(float *)(DAT_803de19c + 0x118) = (float)dVar3;
  return;
}

