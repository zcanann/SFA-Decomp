// Function: FUN_8019c91c
// Entry: 8019c91c
// Size: 252 bytes

undefined4
FUN_8019c91c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  float *pfVar3;
  undefined4 *puVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  local_28 = DAT_802c2a58;
  local_24 = DAT_802c2a5c;
  local_20 = DAT_802c2a60;
  local_1c = DAT_802c2a64;
  if (*(short *)(param_9 + 0xb4) < 0) {
    FUN_800e85f4(param_9);
    uVar1 = 0;
  }
  else {
    if (*(char *)(pfVar3 + 0x2a0) == '\x06') {
      puVar4 = &local_20;
    }
    else {
      puVar4 = &local_28;
    }
    iVar2 = FUN_800805cc(param_11);
    if ((iVar2 == 0x283) ||
       (iVar2 = FUN_80114e4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,param_11,pfVar3,(short)*puVar4,(short)puVar4[1],param_14,param_15,
                             param_16), iVar2 == 0)) {
      if (*(char *)(param_11 + 0x80) == '\x02') {
        iVar2 = FUN_8002bac4();
        FUN_80297184(iVar2,10);
      }
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}

