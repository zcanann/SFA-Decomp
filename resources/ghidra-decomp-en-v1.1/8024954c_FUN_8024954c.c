// Function: FUN_8024954c
// Entry: 8024954c
// Size: 196 bytes

undefined4 FUN_8024954c(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = DAT_803deb78;
  iVar3 = FUN_802493ec(DAT_803deb78,param_1,param_2);
  if (iVar3 == param_2) {
    uVar2 = 0;
    *(undefined *)(param_1 + param_2 + -1) = 0;
  }
  else {
    if ((*(uint *)(DAT_803deb6c + iVar1 * 0xc) & 0xff000000) != 0) {
      if (iVar3 == param_2 + -1) {
        *(undefined *)(param_1 + iVar3) = 0;
        return 0;
      }
      *(undefined *)(param_1 + iVar3) = 0x2f;
      iVar3 = iVar3 + 1;
    }
    *(undefined *)(param_1 + iVar3) = 0;
    uVar2 = 1;
  }
  return uVar2;
}

