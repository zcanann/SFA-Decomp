// Function: FUN_80041ac4
// Entry: 80041ac4
// Size: 612 bytes

void FUN_80041ac4(int param_1)

{
  short sVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  uint local_48;
  int local_44;
  undefined4 local_40;
  undefined4 local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  float local_24;
  undefined4 local_20 [2];
  longlong local_18;
  
  piVar2 = (int *)FUN_8002b588();
  if (FLOAT_803dea04 == *(float *)(param_1 + 8)) {
    DAT_803dcc24 = 0;
  }
  else {
    iVar3 = *piVar2;
    if ((*(ushort *)(iVar3 + 2) & 0x8000) == 0) {
      iVar4 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar4 = *(int *)(param_1 + 0xc4);
      }
      FUN_800403c0(param_1,iVar4,iVar3,0);
    }
    else {
      iVar4 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar4 = *(int *)(param_1 + 0xc4);
      }
      FUN_8003f7f4(param_1,iVar4,iVar3,0);
    }
    iVar3 = param_1;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar4 = iVar4 + 1) {
      if (*(int *)(iVar3 + 200) != 0) {
        FUN_800417c0(*(int *)(iVar3 + 200),param_1,0);
      }
      iVar3 = iVar3 + 4;
    }
    if (((((*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 4) && (DAT_803dcc29 == '\0')) &&
         (sVar1 = *(short *)(param_1 + 0x46), sVar1 != 0x6a8)) &&
        ((sVar1 != 0x6a9 && (sVar1 != 0x6aa)))) &&
       ((sVar1 != 0x6ab && ((sVar1 != 0x6ac && (sVar1 != 0x752)))))) {
      FUN_8000edac((double)(*(float *)(param_1 + 0xc) - FLOAT_803dcdd8),
                   (double)*(float *)(param_1 + 0x10),
                   (double)(*(float *)(param_1 + 0x14) - FLOAT_803dcddc),
                   (double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),&local_30,
                   &local_34,&local_38);
      FUN_8000ea78((double)local_30,(double)local_34,(double)local_38,&local_3c,&local_40,&local_44)
      ;
      iVar3 = FUN_8006fdf8(local_3c,local_40,param_1);
      if (iVar3 < local_44) {
        *(undefined2 *)(*(int *)(param_1 + 100) + 0x36) = 0xffe0;
      }
      else {
        *(undefined2 *)(*(int *)(param_1 + 100) + 0x36) = 0x20;
      }
      iVar4 = *(int *)(param_1 + 100);
      iVar3 = (uint)*(byte *)(iVar4 + 0x40) + (int)*(short *)(iVar4 + 0x36);
      if (iVar3 < 0x100) {
        if (iVar3 < 0) {
          *(undefined *)(iVar4 + 0x40) = 0;
        }
        else {
          *(char *)(iVar4 + 0x40) = (char)iVar3;
        }
      }
      else {
        *(undefined *)(iVar4 + 0x40) = 0xff;
      }
      DAT_803db488 = DAT_803db488 & 0xffffff00 | (uint)*(byte *)(*(int *)(param_1 + 100) + 0x40);
      FUN_8006c5f0(param_1,local_20,&local_24,&local_28,&local_2c);
      local_48 = DAT_803db488;
      local_18 = (longlong)(int)(FLOAT_803dea6c * local_24);
      FUN_80076d78(local_20[0],local_28,local_2c,&local_48,(int)(FLOAT_803dea6c * local_24),1);
    }
  }
  return;
}

