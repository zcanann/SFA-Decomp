// Function: FUN_80177470
// Entry: 80177470
// Size: 108 bytes

undefined4
FUN_80177470(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  
  if (((*(char *)(*(int *)(param_9 + 0x4c) + 0x1d) != '\x02') &&
      (*(char *)(param_11 + 0x80) == '\x01')) &&
     (iVar1 = (int)*(char *)(*(int *)(param_9 + 0x4c) + 0x1a), -1 < iVar1)) {
    FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,'\x01',
                 param_11,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_11 + 0x80) = 0;
  }
  return 0;
}

