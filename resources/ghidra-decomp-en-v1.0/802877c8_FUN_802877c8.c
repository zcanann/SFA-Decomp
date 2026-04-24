// Function: FUN_802877c8
// Entry: 802877c8
// Size: 200 bytes

int FUN_802877c8(int *param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar2 = 0x300;
  *param_2 = 0;
  for (iVar1 = 0; iVar1 < 3; iVar1 = iVar1 + 1) {
    puVar3 = (undefined *)0x0;
    if ((-1 < iVar1) && (iVar1 < 3)) {
      puVar3 = &DAT_803d6920 + iVar1 * 0x890;
    }
    FUN_8028aefc(puVar3);
    if (*(int *)(puVar3 + 4) == 0) {
      *(undefined4 *)(puVar3 + 8) = 0;
      iVar2 = 0;
      *(undefined4 *)(puVar3 + 0xc) = 0;
      *(undefined4 *)(puVar3 + 4) = 1;
      *param_2 = puVar3;
      *param_1 = iVar1;
      iVar1 = 3;
    }
    FUN_8028aef4(puVar3);
  }
  if (iVar2 == 0x300) {
    FUN_80287cd4(s_ERROR___No_buffer_available_802c2958);
  }
  return iVar2;
}

