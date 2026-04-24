// Function: FUN_8000aeb0
// Entry: 8000aeb0
// Size: 576 bytes

undefined4
FUN_8000aeb0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  short *psVar5;
  int iVar6;
  int iVar7;
  undefined2 *puVar8;
  int iVar9;
  int iVar10;
  
  if (DAT_803dd488 == '\0') {
    DAT_803dd488 = '\x01';
    puVar1 = &DAT_80336a20;
    iVar9 = 4;
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
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    DAT_803dd494 = 1;
    DAT_803dd498 = 1;
    DAT_803dd478 = DAT_803dd478 | 0x800;
    uVar2 = FUN_80022e00(0);
    DAT_803dd4a8 = FUN_8001599c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80022e00(uVar2 & 0xff);
  }
  if ((DAT_803dd474 & 0x800) == 0) {
    uVar4 = 0;
  }
  else {
    uVar2 = DAT_803dd48c;
    if ((DAT_803dd48c & 0x1f) != 0) {
      uVar2 = (DAT_803dd48c | 0x1f) + 1;
    }
    DAT_803dd49c = DAT_803dd4a8 + 0x1a0;
    DAT_803dd4a0 = uVar2 - 0x1a0;
    iVar9 = 0x1000000 - DAT_803dd4a0;
    iVar7 = 0;
    iVar3 = 0;
    DAT_803dd4a4 = iVar9;
    do {
      puVar8 = (undefined2 *)0x0;
      iVar6 = 0;
      iVar10 = 100;
      psVar5 = &DAT_802c5e80;
      do {
        if (iVar7 == *psVar5) {
          puVar8 = &DAT_802c5e80 + iVar6 * 8;
          break;
        }
        psVar5 = psVar5 + 8;
        iVar6 = iVar6 + 1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
      if (puVar8 != (undefined2 *)0x0) {
        *(int *)(puVar8 + 4) = iVar9;
        *(undefined4 *)(puVar8 + 6) = *(undefined4 *)(DAT_803dd4a8 + iVar3);
      }
      uVar2 = *(uint *)(puVar8 + 6);
      if ((uVar2 & 0x1f) != 0) {
        uVar2 = (uVar2 | 0x1f) + 1;
      }
      iVar9 = iVar9 + uVar2;
      iVar7 = iVar7 + 1;
      iVar3 = iVar3 + 4;
    } while (iVar7 < 100);
    FUN_80008f38(DAT_803dd49c,DAT_803dd4a4,DAT_803dd4a0);
    uVar4 = FUN_800238f8(0);
    FUN_800238c4(DAT_803dd4a8);
    FUN_800238f8(uVar4);
    uVar4 = 1;
  }
  return uVar4;
}

