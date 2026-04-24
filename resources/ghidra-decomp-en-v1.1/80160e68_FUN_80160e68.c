// Function: FUN_80160e68
// Entry: 80160e68
// Size: 760 bytes

uint FUN_80160e68(short *param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  
  iVar5 = *(int *)(param_1 + 0x26);
  iVar6 = *(int *)(param_1 + 0x5c);
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (param_1[0x5a] != -1) {
      iVar3 = (**(code **)(*DAT_803dd738 + 0x30))(param_1,iVar6,1);
      if (iVar3 == 0) {
        return 1;
      }
      FUN_80160ce8((int)param_1,iVar6,iVar6);
      if (((int)*(short *)(iVar6 + 0x3f6) != 0xffffffff) &&
         (uVar2 = FUN_80020078((int)*(short *)(iVar6 + 0x3f6)), uVar2 != 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x58))(param_3,(int)*(short *)(iVar5 + 0x2c));
        *(undefined2 *)(iVar6 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)(iVar6 + 0x405);
      if (bVar1 == 1) {
        iVar5 = (**(code **)(*DAT_803dd738 + 0x34))
                          (param_1,param_3,iVar6,&DAT_803ad248,&DAT_803ad230,0);
        if (iVar5 != 0) {
          (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3b34,param_1,iVar6,1);
        }
      }
      else if ((bVar1 == 0) || (2 < bVar1)) {
        *(undefined2 *)(param_3 + 0x6e) = 0xffff;
        *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
        pfVar7 = *(float **)(iVar6 + 0x3dc);
        if ((*(ushort *)(iVar6 + 0x400) & 8) != 0) {
          iVar5 = FUN_80010340((double)*(float *)(iVar6 + 0x280),pfVar7);
          if (((iVar5 != 0) || (pfVar7[4] != 0.0)) &&
             (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar7), cVar4 != '\0')) {
            *(ushort *)(iVar6 + 0x400) = *(ushort *)(iVar6 + 0x400) & 0xfff7;
          }
          *(float *)(iVar6 + 0x280) = FLOAT_803e3b30;
          iVar5 = FUN_80021884();
          *param_1 = (short)iVar5 + -0x8000;
          iVar5 = FUN_80021884();
          param_1[1] = (short)iVar5 + 0x4000;
          iVar5 = FUN_80021884();
          param_1[2] = (short)iVar5 + 0x4000;
          *(float *)(param_1 + 6) = pfVar7[0x1a];
          *(float *)(param_1 + 8) = pfVar7[0x1b];
          *(float *)(param_1 + 10) = pfVar7[0x1c];
        }
      }
      else {
        *(undefined2 *)(param_3 + 0x6e) = 0;
        FUN_80160b9c(param_1,param_3,iVar6,iVar6);
        if (*(char *)(iVar6 + 0x405) == '\x01') {
          *(undefined2 *)(iVar6 + 0x270) = 5;
          (**(code **)(*DAT_803dd70c + 8))
                    ((double)FLOAT_803e3b24,(double)FLOAT_803e3b24,param_1,iVar6,&DAT_803ad248,
                     &DAT_803ad230);
          *(undefined *)(param_3 + 0x56) = 0;
        }
      }
    }
    if (param_1[0x5a] == -1) {
      *(ushort *)(iVar6 + 0x400) = *(ushort *)(iVar6 + 0x400) | 2;
      uVar2 = 0;
    }
    else {
      uVar2 = -(uint)*(byte *)(iVar6 + 0x405) >> 0x1f;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

