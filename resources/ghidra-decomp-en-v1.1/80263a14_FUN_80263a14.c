// Function: FUN_80263a14
// Entry: 80263a14
// Size: 544 bytes

int FUN_80263a14(int param_1,char *param_2,uint param_3,int *param_4,undefined *param_5)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  ushort uVar4;
  char *pcVar5;
  ushort uVar6;
  int *local_2c [2];
  
  uVar1 = FUN_80292004((int)param_2);
  if (uVar1 < 0x21) {
    iVar2 = FUN_8025f52c(param_1,local_2c);
    if (-1 < iVar2) {
      if ((param_3 == 0) || (param_3 != (param_3 / (uint)local_2c[0][3]) * local_2c[0][3])) {
        iVar2 = -0x80;
      }
      else {
        uVar6 = 0xffff;
        pcVar3 = (char *)FUN_80261014((int)local_2c[0]);
        pcVar5 = pcVar3;
        for (uVar4 = 0; uVar4 < 0x7f; uVar4 = uVar4 + 1) {
          if (*pcVar5 == -1) {
            if (uVar6 == 0xffff) {
              uVar6 = uVar4;
            }
          }
          else {
            iVar2 = FUN_8028f988((int)pcVar5,local_2c[0][0x43],4);
            if (((iVar2 == 0) &&
                (iVar2 = FUN_8028f988((int)(pcVar5 + 4),local_2c[0][0x43] + 4,2), iVar2 == 0)) &&
               (iVar2 = FUN_80263490((int)pcVar5,param_2), iVar2 != 0)) {
              iVar2 = FUN_8025f5e4(local_2c[0],-7);
              return iVar2;
            }
          }
          pcVar5 = pcVar5 + 0x40;
        }
        if (uVar6 == 0xffff) {
          iVar2 = FUN_8025f5e4(local_2c[0],-8);
        }
        else {
          iVar2 = FUN_80260c10((int)local_2c[0]);
          if (local_2c[0][3] * (uint)*(ushort *)(iVar2 + 6) < param_3) {
            iVar2 = FUN_8025f5e4(local_2c[0],-9);
          }
          else {
            if (param_5 == (undefined *)0x0) {
              param_5 = &DAT_8025e5e4;
            }
            local_2c[0][0x34] = (int)param_5;
            *(ushort *)(local_2c[0] + 0x2f) = uVar6;
            *(short *)(pcVar3 + (uint)uVar6 * 0x40 + 0x38) = (short)(param_3 / (uint)local_2c[0][3])
            ;
            FUN_80291f08((int)(pcVar3 + (uint)uVar6 * 0x40 + 8),(int)param_2,0x20);
            local_2c[0][0x30] = (int)param_4;
            *param_4 = param_1;
            param_4[1] = (uint)uVar6;
            iVar2 = FUN_80260db4(param_1,param_3 / (uint)local_2c[0][3],&LAB_802638e4);
            if (iVar2 < 0) {
              iVar2 = FUN_8025f5e4(local_2c[0],iVar2);
            }
          }
        }
      }
    }
  }
  else {
    iVar2 = -0xc;
  }
  return iVar2;
}

