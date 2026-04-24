// Function: FUN_800a4c38
// Entry: 800a4c38
// Size: 444 bytes

void FUN_800a4c38(void)

{
  undefined2 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  DAT_803dd2a4 = FUN_80054d54(0x16b);
  DAT_803dd2a8 = FUN_80054d54(0x201);
  DAT_8039c2c0 = FUN_80023cc8(0x140,0x15,0);
  DAT_8039c2c4 = FUN_80023cc8(0x140,0x15,0);
  DAT_8039c2c8 = FUN_80023cc8(0x140,0x15,0);
  DAT_8039c2cc = FUN_80023cc8(0x140,0x15,0);
  DAT_8039c2d0 = FUN_80023cc8(0x140,0x15,0);
  DAT_8039c2d4 = FUN_80023cc8(0x140,0x15,0);
  DAT_8039c2d8 = FUN_80023cc8(0x140,0x15,0);
  piVar3 = &DAT_8039c2c0;
  iVar4 = 0;
  do {
    iVar2 = 0;
    iVar5 = 0x14;
    puVar1 = &DAT_8030ffe8;
    do {
      *(undefined2 *)(*piVar3 + iVar2) = *puVar1;
      *(undefined2 *)(*piVar3 + iVar2 + 2) = puVar1[1];
      *(undefined2 *)(*piVar3 + iVar2 + 4) = puVar1[2];
      *(undefined2 *)(*piVar3 + iVar2 + 8) = puVar1[4];
      *(undefined2 *)(*piVar3 + iVar2 + 10) = puVar1[5];
      *(undefined *)(*piVar3 + iVar2 + 0xc) = *(undefined *)(puVar1 + 6);
      *(undefined *)(*piVar3 + iVar2 + 0xd) = *(undefined *)((int)puVar1 + 0xd);
      *(undefined *)(*piVar3 + iVar2 + 0xe) = *(undefined *)(puVar1 + 7);
      *(undefined *)(*piVar3 + iVar2 + 0xf) = 0xff;
      puVar1 = puVar1 + 8;
      iVar2 = iVar2 + 0x10;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    piVar3 = piVar3 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 7);
  return;
}

