// Function: FUN_80160dc4
// Entry: 80160dc4
// Size: 480 bytes

void FUN_80160dc4(short *param_1)

{
  int iVar1;
  char cVar3;
  short sVar2;
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  iVar4 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (*(int *)(param_1 + 0x7c) == 0) {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar4 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(param_1 + 0x7c) = 1;
    }
    else {
      if ((*(ushort *)(iVar5 + 0x400) & 2) != 0) {
        (**(code **)(*DAT_803dcab8 + 0x28))
                  (param_1,iVar5,iVar5 + 0x35c,(int)*(short *)(iVar5 + 0x3f4),iVar5 + 0x405,0,0,0,1)
        ;
        *(ushort *)(iVar5 + 0x400) = *(ushort *)(iVar5 + 0x400) & 0xfffd;
      }
      iVar4 = (**(code **)(*DAT_803dcab8 + 0x30))(param_1,iVar5,1);
      if (iVar4 != 0) {
        FUN_8016083c(param_1,iVar5,iVar5);
        iVar4 = *(int *)(iVar5 + 0x3dc);
        if ((*(ushort *)(iVar5 + 0x400) & 8) != 0) {
          iVar1 = FUN_80010320((double)*(float *)(iVar5 + 0x280),iVar4);
          if (((iVar1 != 0) || (*(int *)(iVar4 + 0x10) != 0)) &&
             (cVar3 = (**(code **)(*DAT_803dca9c + 0x90))(iVar4), cVar3 != '\0')) {
            *(ushort *)(iVar5 + 0x400) = *(ushort *)(iVar5 + 0x400) & 0xfff7;
          }
          *(float *)(iVar5 + 0x280) = FLOAT_803e2e98;
          sVar2 = FUN_800217c0((double)*(float *)(iVar4 + 0x74),(double)*(float *)(iVar4 + 0x7c));
          *param_1 = sVar2 + -0x8000;
          sVar2 = FUN_800217c0((double)*(float *)(iVar4 + 0x7c),(double)*(float *)(iVar4 + 0x78));
          param_1[1] = sVar2 + 0x4000;
          sVar2 = FUN_800217c0((double)*(float *)(iVar4 + 0x78),(double)*(float *)(iVar4 + 0x74));
          param_1[2] = sVar2 + 0x4000;
          *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar4 + 0x68);
          *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0x6c);
          *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar4 + 0x70);
        }
      }
    }
  }
  return;
}

