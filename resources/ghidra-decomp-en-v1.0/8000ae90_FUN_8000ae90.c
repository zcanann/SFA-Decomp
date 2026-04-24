// Function: FUN_8000ae90
// Entry: 8000ae90
// Size: 576 bytes

undefined4 FUN_8000ae90(void)

{
  undefined4 *puVar1;
  undefined uVar4;
  int iVar2;
  undefined4 uVar3;
  uint uVar5;
  short *psVar6;
  int iVar7;
  int iVar8;
  undefined2 *puVar9;
  int iVar10;
  int iVar11;
  
  if (DAT_803dc808 == '\0') {
    DAT_803dc808 = '\x01';
    puVar1 = &DAT_80335dc0;
    iVar10 = 4;
    do {
      *puVar1 = 0xffffffff;
      puVar1[1] = 0xffffffff;
      puVar1[2] = 0;
      *(undefined *)(puVar1 + 4) = 0xff;
      puVar1[3] = 0;
      *(undefined2 *)((int)puVar1 + 0x12) = 0;
      puVar1[6] = 0;
      puVar1[9] = 0xffffffff;
      puVar1[10] = 0xffffffff;
      puVar1[0xb] = 0;
      *(undefined *)(puVar1 + 0xd) = 0xff;
      puVar1[0xc] = 0;
      *(undefined2 *)((int)puVar1 + 0x36) = 0;
      puVar1[0xf] = 0;
      puVar1[0x12] = 0xffffffff;
      puVar1[0x13] = 0xffffffff;
      puVar1[0x14] = 0;
      *(undefined *)(puVar1 + 0x16) = 0xff;
      puVar1[0x15] = 0;
      *(undefined2 *)((int)puVar1 + 0x5a) = 0;
      puVar1[0x18] = 0;
      puVar1[0x1b] = 0xffffffff;
      puVar1[0x1c] = 0xffffffff;
      puVar1[0x1d] = 0;
      *(undefined *)(puVar1 + 0x1f) = 0xff;
      puVar1[0x1e] = 0;
      *(undefined2 *)((int)puVar1 + 0x7e) = 0;
      puVar1[0x21] = 0;
      puVar1 = puVar1 + 0x24;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    DAT_803dc814 = 1;
    DAT_803dc818 = 1;
    DAT_803dc7f8 = DAT_803dc7f8 | 0x800;
    uVar4 = FUN_80022d3c(0);
    DAT_803dc828 = FUN_80015964(s_audio_midi_wad_802c5d64,&DAT_803dc80c,0,FUN_8000a264);
    FUN_80022d3c(uVar4);
  }
  if ((DAT_803dc7f4 & 0x800) == 0) {
    uVar3 = 0;
  }
  else {
    uVar5 = DAT_803dc80c;
    if ((DAT_803dc80c & 0x1f) != 0) {
      uVar5 = (DAT_803dc80c | 0x1f) + 1;
    }
    DAT_803dc81c = DAT_803dc828 + 0x1a0;
    DAT_803dc820 = uVar5 - 0x1a0;
    iVar10 = 0x1000000 - DAT_803dc820;
    iVar8 = 0;
    iVar2 = 0;
    DAT_803dc824 = iVar10;
    do {
      puVar9 = (undefined2 *)0x0;
      iVar7 = 0;
      iVar11 = 100;
      psVar6 = &DAT_802c5700;
      do {
        if (iVar8 == *psVar6) {
          puVar9 = &DAT_802c5700 + iVar7 * 8;
          break;
        }
        psVar6 = psVar6 + 8;
        iVar7 = iVar7 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      if (puVar9 != (undefined2 *)0x0) {
        *(int *)(puVar9 + 4) = iVar10;
        *(undefined4 *)(puVar9 + 6) = *(undefined4 *)(DAT_803dc828 + iVar2);
      }
      uVar5 = *(uint *)(puVar9 + 6);
      if ((uVar5 & 0x1f) != 0) {
        uVar5 = (uVar5 | 0x1f) + 1;
      }
      iVar10 = iVar10 + uVar5;
      iVar8 = iVar8 + 1;
      iVar2 = iVar2 + 4;
    } while (iVar8 < 100);
    FUN_80008f38(DAT_803dc81c,DAT_803dc824,DAT_803dc820);
    uVar3 = FUN_80023834(0);
    FUN_80023800(DAT_803dc828);
    FUN_80023834(uVar3);
    uVar3 = 1;
  }
  return uVar3;
}

