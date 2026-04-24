// Function: FUN_801a6bec
// Entry: 801a6bec
// Size: 196 bytes

undefined4
FUN_801a6bec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = FUN_8002bac4();
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
    if (bVar1 == 2) {
      param_1 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,uVar2,0x138,0,param_13,param_14,param_15,param_16);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      param_1 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,uVar2,0x13b,0,param_13,param_14,param_15,param_16);
    }
  }
  FUN_801a6d2c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  return 0;
}

