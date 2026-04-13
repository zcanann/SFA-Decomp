// Function: FUN_80249300
// Entry: 80249300
// Size: 200 bytes

undefined4
FUN_80249300(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            char *param_9,int param_10)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined auStack_88 [128];
  
  uVar1 = FUN_8024900c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  if ((int)uVar1 < 0) {
    FUN_8024954c((int)auStack_88,0x80);
    FUN_8007d858();
    uVar2 = 0;
  }
  else {
    iVar3 = uVar1 * 0xc;
    if ((*(uint *)(DAT_803deb6c + iVar3) & 0xff000000) == 0) {
      uVar2 = 1;
      *(undefined4 *)(param_10 + 0x30) = *(undefined4 *)(DAT_803deb6c + iVar3 + 4);
      *(undefined4 *)(param_10 + 0x34) = *(undefined4 *)(DAT_803deb6c + iVar3 + 8);
      *(undefined4 *)(param_10 + 0x38) = 0;
      *(undefined4 *)(param_10 + 0xc) = 0;
    }
    else {
      uVar2 = 0;
    }
  }
  return uVar2;
}

