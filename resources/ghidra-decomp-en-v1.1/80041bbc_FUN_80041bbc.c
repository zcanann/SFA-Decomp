// Function: FUN_80041bbc
// Entry: 80041bbc
// Size: 612 bytes

void FUN_80041bbc(int param_1)

{
  short sVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined4 local_48;
  int local_44;
  int local_40;
  int local_3c;
  float local_38;
  float local_34;
  float local_30;
  int local_2c;
  int local_28;
  float local_24;
  undefined4 local_20 [2];
  longlong local_18;
  
  piVar2 = (int *)FUN_8002b660(param_1);
  if (FLOAT_803df684 == *(float *)(param_1 + 8)) {
    DAT_803dd8a4 = 0;
  }
  else {
    iVar3 = *piVar2;
    if ((*(ushort *)(iVar3 + 2) & 0x8000) == 0) {
      iVar4 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar4 = *(int *)(param_1 + 0xc4);
      }
      FUN_800404b8(param_1,iVar4,iVar3,0);
    }
    else {
      iVar4 = param_1;
      if (*(int *)(param_1 + 0xc4) != 0) {
        iVar4 = *(int *)(param_1 + 0xc4);
      }
      FUN_8003f8ec(param_1,iVar4,iVar3);
    }
    iVar3 = param_1;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar4 = iVar4 + 1) {
      if (*(int *)(iVar3 + 200) != 0) {
        FUN_800418b8(*(int *)(iVar3 + 200),param_1,0);
      }
      iVar3 = iVar3 + 4;
    }
    if (((((*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 4) && (DAT_803dd8a9 == '\0')) &&
         (sVar1 = *(short *)(param_1 + 0x46), sVar1 != 0x6a8)) &&
        ((sVar1 != 0x6a9 && (sVar1 != 0x6aa)))) &&
       ((sVar1 != 0x6ab && ((sVar1 != 0x6ac && (sVar1 != 0x752)))))) {
      FUN_8000edcc((double)(*(float *)(param_1 + 0xc) - FLOAT_803dda58),
                   (double)*(float *)(param_1 + 0x10),
                   (double)(*(float *)(param_1 + 0x14) - FLOAT_803dda5c),
                   (double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),&local_30,
                   &local_34,&local_38);
      FUN_8000ea98((double)local_30,(double)local_34,(double)local_38,&local_3c,&local_40,&local_44)
      ;
      iVar3 = FUN_8006ff74(local_3c,local_40,param_1);
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
      DAT_803dc0e8 = CONCAT31(DAT_803dc0e8._0_3_,*(undefined *)(*(int *)(param_1 + 100) + 0x40));
      FUN_8006c76c(param_1,local_20,&local_24,&local_28,&local_2c);
      local_48 = DAT_803dc0e8;
      local_18 = (longlong)(int)(FLOAT_803df6ec * local_24);
      FUN_80076ef4(local_20[0],local_28,local_2c,&local_48,(int)(FLOAT_803df6ec * local_24),1);
    }
  }
  return;
}

