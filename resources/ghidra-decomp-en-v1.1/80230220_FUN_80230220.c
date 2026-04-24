// Function: FUN_80230220
// Entry: 80230220
// Size: 380 bytes

void FUN_80230220(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,char *param_10,uint param_11)

{
  char cVar1;
  int iVar2;
  int iVar3;
  undefined8 extraout_f1;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  cVar1 = *param_10;
  if (cVar1 == '\0') {
    FUN_8000bb38(param_11,0x2a9);
    if (*(short *)(param_11 + 0x46) == 0x601) {
      FUN_8022dd10(param_11,'\x01');
      FUN_8022dbe4(param_11,10);
    }
  }
  else if (cVar1 == '\x01') {
    FUN_8000bb38(param_11,0x2a9);
    if (*(short *)(param_11 + 0x46) == 0x601) {
      FUN_8022dcf8(param_11,'\x01');
      iVar3 = FUN_8022dc44(param_11);
      FUN_8022dd10(param_11,(char)iVar3);
    }
  }
  else if ((cVar1 == '\x03') || (cVar1 == '\x04')) {
    FUN_8000bb38(param_11,0x2a9);
    FUN_80020000((int)*(short *)(iVar3 + 0x1e));
  }
  else {
    FUN_8000bb38(param_11,0x2ab);
    if (*(short *)(param_11 + 0x46) == 0x601) {
      FUN_8022dcb4(param_11);
      FUN_8022dd10(param_11,'\x01');
      FUN_8022dbe4(param_11,0x14);
      iVar3 = FUN_8022dbcc(param_11);
      iVar2 = FUN_8022dbd8(param_11);
      if (iVar2 == iVar3) {
        if (((byte)param_10[0x14] >> 5 & 1) != 0) {
          FUN_80125e88(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,7);
        }
      }
      else if (((byte)param_10[0x14] >> 5 & 1) != 0) {
        FUN_80125e88(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,9);
      }
    }
  }
  param_10[0x15] = '\x02';
  return;
}

