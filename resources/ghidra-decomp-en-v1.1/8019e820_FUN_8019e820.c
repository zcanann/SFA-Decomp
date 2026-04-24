// Function: FUN_8019e820
// Entry: 8019e820
// Size: 212 bytes

void FUN_8019e820(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  char cVar1;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint local_28;
  uint local_24 [6];
  
  cVar1 = *(char *)(*(int *)(param_9 + 0x26) + 0x19);
  if (cVar1 == '\x01') {
    local_24[1] = 0;
    while (iVar2 = FUN_800375e4((int)param_9,local_24,&local_28,local_24 + 1), iVar2 != 0) {
      if (local_24[0] == 0x110004) {
        FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_28,
                     0x110004,(uint)param_9,0,in_r7,in_r8,in_r9,in_r10);
      }
    }
    DAT_803de790 = param_9;
    *param_9 = *param_9 + (ushort)DAT_803dc070 * 0xb6;
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    FUN_8019df6c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

