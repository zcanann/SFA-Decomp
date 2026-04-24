// Function: FUN_802345bc
// Entry: 802345bc
// Size: 388 bytes

void FUN_802345bc(short *param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined local_18;
  undefined local_17;
  undefined local_16 [2];
  float local_14;
  float local_10;
  float local_c;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  local_14 = DAT_802c2608;
  local_10 = DAT_802c260c;
  local_c = DAT_802c2610;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  if (*(int *)(iVar2 + 8) == 0) {
    uVar1 = FUN_8001f4c8(param_1,1);
    *(undefined4 *)(iVar2 + 8) = uVar1;
  }
  if (*(int *)(iVar2 + 8) != 0) {
    FUN_8001db2c(*(int *)(iVar2 + 8),4);
    FUN_8001db34(*(undefined4 *)(iVar2 + 8),*(undefined *)(param_2 + 0x1d));
    FUN_8001dc90((double)local_14,(double)local_10,(double)local_c,*(undefined4 *)(iVar2 + 8));
    if ((*(byte *)(param_2 + 0x2a) & 1) == 0) {
      FUN_8001daf0(*(undefined4 *)(iVar2 + 8),*(undefined *)(param_2 + 0x1a),
                   *(undefined *)(param_2 + 0x1b),*(undefined *)(param_2 + 0x1c),0xff);
      FUN_8001dab8(*(undefined4 *)(iVar2 + 8),*(undefined *)(param_2 + 0x27),
                   *(undefined *)(param_2 + 0x28),*(undefined *)(param_2 + 0x29),0xff);
    }
    else {
      FUN_800898c8(0,local_16,&local_17,&local_18);
      FUN_8001daf0(*(undefined4 *)(iVar2 + 8),local_16[0],local_17,local_18,0xff);
      FUN_8001dab8(*(undefined4 *)(iVar2 + 8),local_16[0],local_17,local_18,0xff);
    }
    FUN_8001db6c((double)FLOAT_803e7250,*(undefined4 *)(iVar2 + 8),*(undefined *)(param_2 + 0x30));
    *(undefined *)(iVar2 + 0xe) = *(undefined *)(param_2 + 0x30);
    FUN_8001d620(*(undefined4 *)(iVar2 + 8),*(undefined *)(param_2 + 0x26),
                 (int)*(short *)(param_2 + 0x2e));
    if (*(char *)(param_2 + 0x2c) != '\0') {
      FUN_8001db5c(*(undefined4 *)(iVar2 + 8));
    }
  }
  return;
}

