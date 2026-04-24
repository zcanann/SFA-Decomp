// Function: FUN_8017bcf8
// Entry: 8017bcf8
// Size: 180 bytes

undefined4 FUN_8017bcf8(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_3 + 0x80) != '\0') {
    if (((*(byte *)(iVar1 + 0x1b) & 4) != 0) && (*(char *)(param_3 + 0x80) == '\x01')) {
      FUN_800200e8((int)*(short *)(iVar1 + 0x1c),1);
    }
    if ((*(char *)(param_3 + 0x80) == '\x02') && (*(short *)(iVar1 + 0x24) != 0)) {
      (**(code **)(*DAT_803dca54 + 0x58))(param_3);
    }
    *(undefined *)(param_3 + 0x80) = 0;
  }
  *(undefined4 *)(param_1 + 0xf8) = 0;
  return 0;
}

