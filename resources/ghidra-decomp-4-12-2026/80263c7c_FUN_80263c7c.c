// Function: FUN_80263c7c
// Entry: 80263c7c
// Size: 440 bytes

int FUN_80263c7c(int *param_1,int param_2,uint param_3,undefined4 *param_4)

{
  int iVar1;
  int iVar2;
  int *local_18 [2];
  
  iVar1 = FUN_8025f52c(*param_1,local_18);
  if (-1 < iVar1) {
    if (((*(ushort *)(param_1 + 4) < 5) ||
        ((uint)*(ushort *)(local_18[0] + 4) <= (uint)*(ushort *)(param_1 + 4))) ||
       ((int)((uint)*(ushort *)(local_18[0] + 4) * local_18[0][3]) <= param_1[2])) {
      iVar1 = FUN_8025f5e4(local_18[0],-0x80);
    }
    else {
      iVar1 = FUN_80261014((int)local_18[0]);
      iVar1 = iVar1 + param_1[1] * 0x40;
      iVar2 = (uint)*(ushort *)(iVar1 + 0x38) * local_18[0][3];
      if (((int)param_3 < iVar2) && ((int)(param_3 + param_2) <= iVar2)) {
        local_18[0][0x30] = (int)param_1;
        param_1[3] = param_2;
        if ((int)param_3 < param_1[2]) {
          param_1[2] = 0;
          *(undefined2 *)(param_1 + 4) = *(undefined2 *)(iVar1 + 0x36);
          if ((*(ushort *)(param_1 + 4) < 5) ||
             (*(ushort *)(local_18[0] + 4) <= *(ushort *)(param_1 + 4))) {
            iVar1 = FUN_8025f5e4(local_18[0],-6);
            return iVar1;
          }
        }
        iVar1 = FUN_80260c10((int)local_18[0]);
        do {
          if ((param_3 & ~(local_18[0][3] - 1U)) <= (uint)param_1[2]) {
            param_1[2] = param_3;
            *param_4 = local_18[0];
            return 0;
          }
          param_1[2] = param_1[2] + local_18[0][3];
          *(undefined2 *)(param_1 + 4) = *(undefined2 *)(iVar1 + (uint)*(ushort *)(param_1 + 4) * 2)
          ;
        } while ((4 < *(ushort *)(param_1 + 4)) &&
                (*(ushort *)(param_1 + 4) < *(ushort *)(local_18[0] + 4)));
        iVar1 = FUN_8025f5e4(local_18[0],-6);
      }
      else {
        iVar1 = FUN_8025f5e4(local_18[0],-0xb);
      }
    }
  }
  return iVar1;
}

