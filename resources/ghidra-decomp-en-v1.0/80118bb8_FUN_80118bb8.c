// Function: FUN_80118bb8
// Entry: 80118bb8
// Size: 208 bytes

void FUN_80118bb8(void)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  
  puVar3 = &DAT_803a5d60;
  if (DAT_803a5e08 == 0) {
    iVar1 = 0;
    do {
      FUN_801194bc(puVar3 + 0xf4);
      puVar3 = puVar3 + 8;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 10);
  }
  iVar1 = 0;
  puVar2 = &DAT_803a5d60;
  puVar3 = puVar2;
  do {
    FUN_80119768(puVar3 + 0x144);
    puVar3 = puVar3 + 0x10;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 3);
  if (DAT_803a5dff != '\0') {
    iVar1 = 0;
    do {
      FUN_80117350(puVar2 + 0x174);
      puVar2 = puVar2 + 0x10;
      iVar1 = iVar1 + 1;
    } while (iVar1 < 3);
  }
  FUN_80244000(&DAT_803a5cec,&DAT_803dd67c,1);
  return;
}

