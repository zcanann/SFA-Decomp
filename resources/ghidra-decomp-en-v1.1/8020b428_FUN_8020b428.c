// Function: FUN_8020b428
// Entry: 8020b428
// Size: 308 bytes

void FUN_8020b428(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  float local_18;
  float local_14;
  float local_10 [2];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  FUN_8003b9ec(param_1);
  FUN_80038524(param_1,0,(float *)(iVar4 + 0x1c),(undefined4 *)(iVar4 + 0x20),
               (float *)(iVar4 + 0x24),0);
  if (*(int *)(iVar4 + 0x160) != 0) {
    FUN_80038524(param_1,5,&local_18,&local_14,local_10,0);
    FUN_8001de4c((double)local_18,(double)local_14,(double)local_10[0],*(int **)(iVar4 + 0x160));
    iVar2 = *(int *)(iVar4 + 0x160);
    if ((*(char *)(iVar2 + 0x2f8) != '\0') && (*(char *)(iVar2 + 0x4c) != '\0')) {
      iVar3 = (uint)*(byte *)(iVar2 + 0x2f9) + (int)*(char *)(iVar2 + 0x2fa);
      if (iVar3 < 0) {
        iVar3 = 0;
        *(undefined *)(iVar2 + 0x2fa) = 0;
      }
      else if (0xc < iVar3) {
        uVar1 = FUN_80022264(0xfffffff4,0xc);
        iVar3 = iVar3 + uVar1;
        if (0xff < iVar3) {
          iVar3 = 0xff;
          *(undefined *)(*(int *)(iVar4 + 0x160) + 0x2fa) = 0;
        }
      }
      *(char *)(*(int *)(iVar4 + 0x160) + 0x2f9) = (char)iVar3;
    }
    iVar4 = *(int *)(iVar4 + 0x160);
    if ((*(char *)(iVar4 + 0x2f8) != '\0') && (*(char *)(iVar4 + 0x4c) != '\0')) {
      FUN_80060630(iVar4);
    }
  }
  return;
}

