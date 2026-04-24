// Function: FUN_80287f2c
// Entry: 80287f2c
// Size: 200 bytes

int FUN_80287f2c(int *param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar2 = 0x300;
  *param_2 = 0;
  for (iVar1 = 0; iVar1 < 3; iVar1 = iVar1 + 1) {
    puVar3 = (undefined *)0x0;
    if ((-1 < iVar1) && (iVar1 < 3)) {
      puVar3 = &DAT_803d7580 + iVar1 * 0x890;
    }
    FUN_8028b660();
    if (*(int *)(puVar3 + 4) == 0) {
      *(undefined4 *)(puVar3 + 8) = 0;
      iVar2 = 0;
      *(undefined4 *)(puVar3 + 0xc) = 0;
      *(undefined4 *)(puVar3 + 4) = 1;
      *param_2 = puVar3;
      *param_1 = iVar1;
      iVar1 = 3;
    }
    FUN_8028b658();
  }
  if (iVar2 == 0x300) {
    FUN_80288438(s_ERROR___No_buffer_available_802c30d8);
  }
  return iVar2;
}

