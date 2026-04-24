// Function: FUN_80161270
// Entry: 80161270
// Size: 480 bytes

void FUN_80161270(short *param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar2 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (*(int *)(param_1 + 0x7c) == 0) {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar2 + 0x10);
      param_1[0x7c] = 0;
      param_1[0x7d] = 1;
    }
    else {
      if ((*(ushort *)(iVar3 + 0x400) & 2) != 0) {
        (**(code **)(*DAT_803dd738 + 0x28))
                  (param_1,iVar3,iVar3 + 0x35c,(int)*(short *)(iVar3 + 0x3f4),iVar3 + 0x405,0,0,0,1)
        ;
        *(ushort *)(iVar3 + 0x400) = *(ushort *)(iVar3 + 0x400) & 0xfffd;
      }
      iVar2 = (**(code **)(*DAT_803dd738 + 0x30))(param_1,iVar3,1);
      if (iVar2 != 0) {
        FUN_80160ce8((int)param_1,iVar3,iVar3);
        pfVar4 = *(float **)(iVar3 + 0x3dc);
        if ((*(ushort *)(iVar3 + 0x400) & 8) != 0) {
          iVar2 = FUN_80010340((double)*(float *)(iVar3 + 0x280),pfVar4);
          if (((iVar2 != 0) || (pfVar4[4] != 0.0)) &&
             (cVar1 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar1 != '\0')) {
            *(ushort *)(iVar3 + 0x400) = *(ushort *)(iVar3 + 0x400) & 0xfff7;
          }
          *(float *)(iVar3 + 0x280) = FLOAT_803e3b30;
          iVar2 = FUN_80021884();
          *param_1 = (short)iVar2 + -0x8000;
          iVar2 = FUN_80021884();
          param_1[1] = (short)iVar2 + 0x4000;
          iVar2 = FUN_80021884();
          param_1[2] = (short)iVar2 + 0x4000;
          *(float *)(param_1 + 6) = pfVar4[0x1a];
          *(float *)(param_1 + 8) = pfVar4[0x1b];
          *(float *)(param_1 + 10) = pfVar4[0x1c];
        }
      }
    }
  }
  return;
}

