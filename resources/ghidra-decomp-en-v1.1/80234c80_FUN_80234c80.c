// Function: FUN_80234c80
// Entry: 80234c80
// Size: 388 bytes

void FUN_80234c80(short *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  undefined local_18;
  undefined local_17;
  undefined local_16 [2];
  float local_14;
  float local_10;
  float local_c;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  local_14 = DAT_802c2d88;
  local_10 = DAT_802c2d8c;
  local_c = DAT_802c2d90;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  if (*(int *)(iVar2 + 8) == 0) {
    piVar1 = FUN_8001f58c((int)param_1,'\x01');
    *(int **)(iVar2 + 8) = piVar1;
  }
  if (*(int *)(iVar2 + 8) != 0) {
    FUN_8001dbf0(*(int *)(iVar2 + 8),4);
    FUN_8001dbf8(*(int *)(iVar2 + 8),(uint)*(byte *)(param_2 + 0x1d));
    FUN_8001dd54((double)local_14,(double)local_10,(double)local_c,*(int **)(iVar2 + 8));
    if ((*(byte *)(param_2 + 0x2a) & 1) == 0) {
      FUN_8001dbb4(*(int *)(iVar2 + 8),*(undefined *)(param_2 + 0x1a),*(undefined *)(param_2 + 0x1b)
                   ,*(undefined *)(param_2 + 0x1c),0xff);
      FUN_8001db7c(*(int *)(iVar2 + 8),*(undefined *)(param_2 + 0x27),*(undefined *)(param_2 + 0x28)
                   ,*(undefined *)(param_2 + 0x29),0xff);
    }
    else {
      FUN_80089b54(0,local_16,&local_17,&local_18);
      FUN_8001dbb4(*(int *)(iVar2 + 8),local_16[0],local_17,local_18,0xff);
      FUN_8001db7c(*(int *)(iVar2 + 8),local_16[0],local_17,local_18,0xff);
    }
    FUN_8001dc30((double)FLOAT_803e7ee8,*(int *)(iVar2 + 8),*(char *)(param_2 + 0x30));
    *(undefined *)(iVar2 + 0xe) = *(undefined *)(param_2 + 0x30);
    FUN_8001d6e4(*(int *)(iVar2 + 8),(uint)*(byte *)(param_2 + 0x26),*(short *)(param_2 + 0x2e));
    if (*(char *)(param_2 + 0x2c) != '\0') {
      FUN_8001dc20(*(int *)(iVar2 + 8),*(char *)(param_2 + 0x2c));
    }
  }
  return;
}

