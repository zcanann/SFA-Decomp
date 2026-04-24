// Function: FUN_80106f78
// Entry: 80106f78
// Size: 340 bytes

void FUN_80106f78(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  longlong local_18;
  
  if (*(int *)(param_2 + 0xc0) == 0) {
    uVar2 = FUN_80014e70(0);
    if ((((*(int *)(param_1 + 0x124) == 0) ||
         (((sVar1 = *(short *)(*(int *)(param_1 + 0x124) + 0x44), sVar1 != 0x1c && (sVar1 != 0x2a))
          || (*(short *)(param_2 + 0x44) != 1)))) || (iVar3 = FUN_80296700(param_2), iVar3 == 0)) &&
       ((*(byte *)(param_1 + 0x141) & 2) == 0)) {
      if ((((uVar2 & 0x10) != 0) && (*(short *)(param_2 + 0x44) == 1)) &&
         (iVar3 = FUN_802962b4(param_2), iVar3 != 0)) {
        local_28 = *(undefined4 *)(DAT_803dd538 + 4);
        local_24 = *(undefined4 *)(DAT_803dd538 + 0xc);
        local_18 = (longlong)(int)*(float *)(DAT_803dd538 + 0x10);
        local_20 = (undefined2)(int)*(float *)(DAT_803dd538 + 0x10);
        (**(code **)(*DAT_803dca50 + 0x1c))(0x44,1,0,0xc,&local_28,0,0xff);
      }
    }
    else {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
    }
  }
  return;
}

