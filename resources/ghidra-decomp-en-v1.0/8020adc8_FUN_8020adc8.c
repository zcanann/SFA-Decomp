// Function: FUN_8020adc8
// Entry: 8020adc8
// Size: 308 bytes

void FUN_8020adc8(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  float local_18;
  float local_14;
  float local_10 [2];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_8003b8f4((double)FLOAT_803e651c);
  FUN_8003842c(param_1,0,iVar3 + 0x1c,iVar3 + 0x20,iVar3 + 0x24,0);
  if (*(int *)(iVar3 + 0x160) != 0) {
    FUN_8003842c(param_1,5,&local_18,&local_14,local_10,0);
    FUN_8001dd88((double)local_18,(double)local_14,(double)local_10[0],
                 *(undefined4 *)(iVar3 + 0x160));
    iVar1 = *(int *)(iVar3 + 0x160);
    if ((*(char *)(iVar1 + 0x2f8) != '\0') && (*(char *)(iVar1 + 0x4c) != '\0')) {
      iVar2 = (uint)*(byte *)(iVar1 + 0x2f9) + (int)*(char *)(iVar1 + 0x2fa);
      if (iVar2 < 0) {
        iVar2 = 0;
        *(undefined *)(iVar1 + 0x2fa) = 0;
      }
      else if (0xc < iVar2) {
        iVar1 = FUN_800221a0(0xfffffff4,0xc);
        iVar2 = iVar2 + iVar1;
        if (0xff < iVar2) {
          iVar2 = 0xff;
          *(undefined *)(*(int *)(iVar3 + 0x160) + 0x2fa) = 0;
        }
      }
      *(char *)(*(int *)(iVar3 + 0x160) + 0x2f9) = (char)iVar2;
    }
    if ((*(char *)(*(int *)(iVar3 + 0x160) + 0x2f8) != '\0') &&
       (*(char *)(*(int *)(iVar3 + 0x160) + 0x4c) != '\0')) {
      FUN_800604b4();
    }
  }
  return;
}

