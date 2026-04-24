// Function: FUN_8019c5a0
// Entry: 8019c5a0
// Size: 476 bytes

void FUN_8019c5a0(undefined2 *param_1,int param_2)

{
  undefined uVar2;
  int iVar1;
  int iVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined2 local_14;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  local_1c = DAT_802c22c0;
  local_18 = DAT_802c22c4;
  local_14 = DAT_802c22c8;
  local_28 = DAT_802c22cc;
  local_24 = DAT_802c22d0;
  local_20 = DAT_802c22d4;
  if (iVar3 != 0) {
    FUN_80037964(param_1,4);
    uVar2 = FUN_8001ffb4(0x4b);
    *(undefined *)(iVar3 + 0xa80) = uVar2;
    *(undefined4 *)(param_1 + 0x7a) = 1;
    *(code **)(param_1 + 0x5e) = FUN_8019c3a0;
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    *(undefined4 *)(iVar3 + 0xa94) = 0;
    *(float *)(iVar3 + 0x7fc) = FLOAT_803e4110;
    *(undefined4 *)(iVar3 + 0xa90) = 6;
    *(undefined *)(iVar3 + 0xa9b) = 0;
    *(byte *)(iVar3 + 0x611) = *(byte *)(iVar3 + 0x611) | 0x28;
    *(undefined *)(iVar3 + 0xa98) = 1;
    *(undefined *)(iVar3 + 0xa99) = 0;
    *(undefined *)(iVar3 + 0xa9a) = 0;
    iVar1 = FUN_8001ffb4(0x57);
    if (iVar1 == 0) {
      iVar1 = FUN_8001ffb4(0x60);
      if ((iVar1 != 0) && (*(char *)(param_2 + 0x19) == '\0')) {
        *(undefined *)(iVar3 + 0xa80) = 4;
        FUN_80114184(8,param_1);
      }
    }
    else {
      *(undefined *)(iVar3 + 0xa80) = 4;
      if (*(char *)(param_2 + 0x19) == '\0') {
        param_1[3] = param_1[3] | 0x4000;
        FUN_8002ce88(param_1);
      }
    }
    FUN_80035f20(param_1);
    FUN_80114f64(param_1,iVar3,0xffffe000,0x2800,4);
    FUN_8011507c(iVar3,300,100);
    FUN_80113f9c(iVar3,&local_28,&local_1c,4);
    FUN_80080078(&DAT_8032284c,0xf);
    *(byte *)(iVar3 + 0x611) = *(byte *)(iVar3 + 0x611) | 2;
  }
  return;
}

