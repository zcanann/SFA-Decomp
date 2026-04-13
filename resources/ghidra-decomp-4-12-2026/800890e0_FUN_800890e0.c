// Function: FUN_800890e0
// Entry: 800890e0
// Size: 476 bytes

/* WARNING: Removing unreachable block (ram,0x80089298) */
/* WARNING: Removing unreachable block (ram,0x800890f0) */

void FUN_800890e0(double param_1,uint param_2)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  int iVar6;
  
  puVar4 = FUN_800e877c();
  if (*(byte *)(DAT_803dddac + 0x24c) != param_2) {
    *(byte *)(DAT_803dddac + 0x24d) = *(byte *)(DAT_803dddac + 0x24c);
    *(char *)(DAT_803dddac + 0x24c) = (char)param_2;
    fVar3 = FLOAT_803dfcdc;
    fVar2 = FLOAT_803dfcd8;
    if (param_1 == (double)FLOAT_803dfcd8) {
      *(float *)(DAT_803dddac + 0x248) = FLOAT_803dfcdc;
      *(float *)(DAT_803dddac + 0x244) = fVar3;
    }
    else {
      *(float *)(DAT_803dddac + 0x248) = FLOAT_803dfcdc / (float)((double)FLOAT_803dfce0 * param_1);
      *(float *)(DAT_803dddac + 0x244) = fVar2;
    }
    bVar1 = *(byte *)(DAT_803dddac + param_2 * 0xa4 + 0xc1) >> 3;
    if ((bVar1 & 3) != 0) {
      FUN_8005d06c((bVar1 & 3) - 1);
    }
    iVar6 = param_2 * 0xa4 + 0xc1;
    *(byte *)(DAT_803dddac + 0x209) =
         *(byte *)(DAT_803dddac + iVar6) & 0x80 | *(byte *)(DAT_803dddac + 0x209) & 0x7f;
    *(byte *)(DAT_803dddac + 0x209) =
         (byte)((*(byte *)(DAT_803dddac + iVar6) >> 5 & 1) << 5) |
         *(byte *)(DAT_803dddac + 0x209) & 0xdf;
    puVar5 = FUN_800e877c();
    iVar6 = FUN_800e8a48();
    if (iVar6 == 0) {
      if (*(char *)(DAT_803dddac + 0xc1) < '\0') {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) | 2;
      }
      else {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) & 0xfd;
      }
      if (*(char *)(DAT_803dddac + 0x165) < '\0') {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) | 4;
      }
      else {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) & 0xfb;
      }
    }
    if (param_2 == 0) {
      *(byte *)(puVar4 + 0x10) = *(byte *)(puVar4 + 0x10) & 0xef;
    }
    else {
      *(byte *)(puVar4 + 0x10) = *(byte *)(puVar4 + 0x10) | 0x10;
    }
  }
  return;
}

