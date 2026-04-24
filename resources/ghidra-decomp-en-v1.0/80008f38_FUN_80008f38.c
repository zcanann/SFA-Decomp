// Function: FUN_80008f38
// Entry: 80008f38
// Size: 208 bytes

void FUN_80008f38(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc7b8 + 1;
  iVar1 = DAT_803dc7b8 * 0x30;
  DAT_803dc7b8 = iVar2;
  if (0xf < iVar2) {
    DAT_803dc7b8 = 0;
  }
  if ((param_3 & 0x1f) != 0) {
    param_3 = (param_3 | 0x1f) + 1;
  }
  FUN_802419e8(param_1,param_3);
  DAT_803dc7bc = 0;
  FUN_80250d64(&DAT_80335940 + iVar1,100,0,1,param_1,param_2,param_3,&LAB_80009008);
  do {
  } while (DAT_803dc7bc == 0);
  return;
}

