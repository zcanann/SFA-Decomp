// Function: FUN_80248b9c
// Entry: 80248b9c
// Size: 200 bytes

undefined4 FUN_80248b9c(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack136 [128];
  
  iVar1 = FUN_802488a8();
  if (iVar1 < 0) {
    FUN_80248de8(auStack136,0x80);
    FUN_8007d6dc(s_Warning__DVDOpen____file___s__wa_8032d8f8,param_1,auStack136);
    uVar2 = 0;
  }
  else {
    iVar1 = iVar1 * 0xc;
    if ((*(uint *)(DAT_803ddeec + iVar1) & 0xff000000) == 0) {
      uVar2 = 1;
      *(undefined4 *)(param_2 + 0x30) = *(undefined4 *)(DAT_803ddeec + iVar1 + 4);
      *(undefined4 *)(param_2 + 0x34) = *(undefined4 *)(DAT_803ddeec + iVar1 + 8);
      *(undefined4 *)(param_2 + 0x38) = 0;
      *(undefined4 *)(param_2 + 0xc) = 0;
    }
    else {
      uVar2 = 0;
    }
  }
  return uVar2;
}

