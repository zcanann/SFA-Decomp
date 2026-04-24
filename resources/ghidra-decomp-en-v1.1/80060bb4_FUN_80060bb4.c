// Function: FUN_80060bb4
// Entry: 80060bb4
// Size: 264 bytes

int FUN_80060bb4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)

{
  uint uVar1;
  int iVar2;
  undefined4 in_r10;
  uint uVar3;
  int local_18;
  uint local_14 [3];
  
  if (DAT_803ddb30 < param_9) {
    iVar2 = 0;
  }
  else {
    uVar3 = 0;
    if (DAT_803dda64 != 0) {
      uVar1 = *(uint *)(DAT_803dda64 + param_9 * 4);
      if (uVar1 != 0xffffffff) {
        if ((uVar1 == 0) && (*(int *)(DAT_803dda64 + param_9 * 4 + 4) == 0)) {
          return 0;
        }
        param_1 = FUN_80048d78(uVar1,local_14,&local_18);
        uVar3 = uVar1;
      }
    }
    if ((int)local_14[0] < 1) {
      iVar2 = 0;
    }
    else if (local_18 < 0x32001) {
      iVar2 = FUN_80023d8c(local_18,5);
      if (iVar2 == 0) {
        iVar2 = 0;
      }
      else {
        FUN_80046644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x25,iVar2,
                     uVar3,local_14[0],(uint *)0x0,0,0,in_r10);
      }
    }
    else {
      iVar2 = 0;
    }
  }
  return iVar2;
}

