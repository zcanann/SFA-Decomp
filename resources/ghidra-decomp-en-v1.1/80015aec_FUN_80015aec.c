// Function: FUN_80015aec
// Entry: 80015aec
// Size: 276 bytes

uint FUN_80015aec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char *param_9,int *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int aiStack_58 [13];
  int local_24;
  
  if (param_10 != (int *)0x0) {
    *param_10 = 0;
  }
  FUN_8024bb7c(1);
  iVar2 = FUN_80249300(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       (int)aiStack_58);
  if (iVar2 == 0) {
    uVar3 = 0;
  }
  else {
    uVar1 = local_24 + 0x1fU & 0xffffffe0;
    uVar3 = FUN_80023d8c(uVar1,0x7d7d7d7d);
    if (uVar3 == 0) {
      uVar3 = 0;
    }
    else {
      iVar2 = FUN_80015888(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           aiStack_58,uVar3,uVar1,0,param_13,param_14,param_15,param_16);
      if (iVar2 == -1) {
        FUN_800238c4(uVar3);
        uVar3 = 0;
      }
      else {
        iVar2 = FUN_802493c8(aiStack_58);
        if (iVar2 == 0) {
          FUN_800238c4(uVar3);
          uVar3 = 0;
        }
        else {
          FUN_80242114(uVar3,local_24);
          if (param_10 != (int *)0x0) {
            *param_10 = local_24;
          }
        }
      }
    }
  }
  return uVar3;
}

