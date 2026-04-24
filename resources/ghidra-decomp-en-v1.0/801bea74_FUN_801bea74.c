// Function: FUN_801bea74
// Entry: 801bea74
// Size: 508 bytes

void FUN_801bea74(int param_1)

{
  short sVar1;
  undefined4 uVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  undefined uStack16;
  undefined local_f;
  undefined local_e;
  undefined local_d [5];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(int *)(param_1 + 0xf4) == 0) {
    if (*(int *)(param_1 + 0xf8) == 0) {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar4 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar4 + 0x2e),param_1,0xffffffff);
      *(undefined4 *)(param_1 + 0xf8) = 1;
    }
    else {
      if ((*(ushort *)(iVar5 + 0x400) & 2) != 0) {
        FLOAT_803ddba4 = FLOAT_803e4cc8;
        (**(code **)(*DAT_803dcab8 + 0x28))
                  (param_1,iVar5,iVar5 + 0x35c,(int)*(short *)(iVar5 + 0x3f4),iVar5 + 0x405,0,0,0,1)
        ;
        *(ushort *)(iVar5 + 0x400) = *(ushort *)(iVar5 + 0x400) & 0xfffd;
      }
      iVar4 = (**(code **)(*DAT_803dcab8 + 0x30))(param_1,iVar5,1);
      if (iVar4 != 0) {
        uVar2 = FUN_8002b9ec();
        *(undefined4 *)(iVar5 + 0x2d0) = uVar2;
        FUN_801be19c(param_1,0,iVar5,iVar5);
        if (DAT_803ddb90 != 0) {
          FUN_8001d9f4(DAT_803ddb90,local_d,&local_e,&local_f,&uStack16);
          FUN_8001d71c(DAT_803ddb90,local_d[0],local_e,local_f,0xc0);
          if ((*(char *)(DAT_803ddb90 + 0x2f8) != '\0') && (*(char *)(DAT_803ddb90 + 0x4c) != '\0'))
          {
            sVar1 = (ushort)*(byte *)(DAT_803ddb90 + 0x2f9) + (short)*(char *)(DAT_803ddb90 + 0x2fa)
            ;
            if (sVar1 < 0) {
              sVar1 = 0;
              *(undefined *)(DAT_803ddb90 + 0x2fa) = 0;
            }
            else if (0xc < sVar1) {
              sVar3 = FUN_800221a0(0xfffffff4,0xc);
              sVar1 = sVar1 + sVar3;
              if (0xff < sVar1) {
                sVar1 = 0xff;
                *(undefined *)(DAT_803ddb90 + 0x2fa) = 0;
              }
            }
            *(char *)(DAT_803ddb90 + 0x2f9) = (char)sVar1;
          }
        }
      }
    }
  }
  return;
}

