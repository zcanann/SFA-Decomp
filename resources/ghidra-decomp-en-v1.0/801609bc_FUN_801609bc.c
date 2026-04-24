// Function: FUN_801609bc
// Entry: 801609bc
// Size: 760 bytes

uint FUN_801609bc(short *param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  char cVar5;
  short sVar4;
  int iVar6;
  int iVar7;
  
  iVar6 = *(int *)(param_1 + 0x26);
  iVar7 = *(int *)(param_1 + 0x5c);
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (param_1[0x5a] != -1) {
      iVar3 = (**(code **)(*DAT_803dcab8 + 0x30))(param_1,iVar7,1);
      if (iVar3 == 0) {
        return 1;
      }
      FUN_8016083c(param_1,iVar7,iVar7);
      if ((*(short *)(iVar7 + 0x3f6) != -1) && (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
        (**(code **)(*DAT_803dca54 + 0x58))(param_3,(int)*(short *)(iVar6 + 0x2c));
        *(undefined2 *)(iVar7 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)(iVar7 + 0x405);
      if (bVar1 == 1) {
        iVar6 = (**(code **)(*DAT_803dcab8 + 0x34))
                          (param_1,param_3,iVar7,&DAT_803ac5e8,&DAT_803ac5d0,0);
        if (iVar6 != 0) {
          (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e2e9c,param_1,iVar7,1);
        }
      }
      else if ((bVar1 == 0) || (2 < bVar1)) {
        *(undefined2 *)(param_3 + 0x6e) = 0xffff;
        *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
        iVar6 = *(int *)(iVar7 + 0x3dc);
        if ((*(ushort *)(iVar7 + 0x400) & 8) != 0) {
          iVar3 = FUN_80010320((double)*(float *)(iVar7 + 0x280),iVar6);
          if (((iVar3 != 0) || (*(int *)(iVar6 + 0x10) != 0)) &&
             (cVar5 = (**(code **)(*DAT_803dca9c + 0x90))(iVar6), cVar5 != '\0')) {
            *(ushort *)(iVar7 + 0x400) = *(ushort *)(iVar7 + 0x400) & 0xfff7;
          }
          *(float *)(iVar7 + 0x280) = FLOAT_803e2e98;
          sVar4 = FUN_800217c0((double)*(float *)(iVar6 + 0x74),(double)*(float *)(iVar6 + 0x7c));
          *param_1 = sVar4 + -0x8000;
          sVar4 = FUN_800217c0((double)*(float *)(iVar6 + 0x7c),(double)*(float *)(iVar6 + 0x78));
          param_1[1] = sVar4 + 0x4000;
          sVar4 = FUN_800217c0((double)*(float *)(iVar6 + 0x78),(double)*(float *)(iVar6 + 0x74));
          param_1[2] = sVar4 + 0x4000;
          *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar6 + 0x68);
          *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar6 + 0x6c);
          *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar6 + 0x70);
        }
      }
      else {
        *(undefined2 *)(param_3 + 0x6e) = 0;
        FUN_801606f0(param_1,param_3,iVar7,iVar7);
        if (*(char *)(iVar7 + 0x405) == '\x01') {
          *(undefined2 *)(iVar7 + 0x270) = 5;
          (**(code **)(*DAT_803dca8c + 8))
                    ((double)FLOAT_803e2e8c,(double)FLOAT_803e2e8c,param_1,iVar7,&DAT_803ac5e8,
                     &DAT_803ac5d0);
          *(undefined *)(param_3 + 0x56) = 0;
        }
      }
    }
    if (param_1[0x5a] == -1) {
      *(ushort *)(iVar7 + 0x400) = *(ushort *)(iVar7 + 0x400) | 2;
      uVar2 = 0;
    }
    else {
      uVar2 = -(uint)*(byte *)(iVar7 + 0x405) >> 0x1f;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

