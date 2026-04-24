// Function: FUN_80263518
// Entry: 80263518
// Size: 440 bytes

int FUN_80263518(undefined4 *param_1,int param_2,uint param_3,int *param_4)

{
  int iVar1;
  int iVar2;
  int local_18 [2];
  
  iVar1 = FUN_8025edc8(*param_1,local_18);
  if (-1 < iVar1) {
    if (((*(ushort *)(param_1 + 4) < 5) ||
        ((uint)*(ushort *)(local_18[0] + 0x10) <= (uint)*(ushort *)(param_1 + 4))) ||
       ((int)((uint)*(ushort *)(local_18[0] + 0x10) * *(int *)(local_18[0] + 0xc)) <=
        (int)param_1[2])) {
      iVar1 = FUN_8025ee80(local_18[0],0xffffff80);
    }
    else {
      iVar1 = FUN_802608b0();
      iVar1 = iVar1 + param_1[1] * 0x40;
      iVar2 = (uint)*(ushort *)(iVar1 + 0x38) * *(int *)(local_18[0] + 0xc);
      if (((int)param_3 < iVar2) && ((int)(param_3 + param_2) <= iVar2)) {
        *(undefined4 **)(local_18[0] + 0xc0) = param_1;
        param_1[3] = param_2;
        if ((int)param_3 < (int)param_1[2]) {
          param_1[2] = 0;
          *(undefined2 *)(param_1 + 4) = *(undefined2 *)(iVar1 + 0x36);
          if ((*(ushort *)(param_1 + 4) < 5) ||
             (*(ushort *)(local_18[0] + 0x10) <= *(ushort *)(param_1 + 4))) {
            iVar1 = FUN_8025ee80(local_18[0],0xfffffffa);
            return iVar1;
          }
        }
        iVar1 = FUN_802604ac(local_18[0]);
        do {
          if ((param_3 & ~(*(int *)(local_18[0] + 0xc) - 1U)) <= (uint)param_1[2]) {
            param_1[2] = param_3;
            *param_4 = local_18[0];
            return 0;
          }
          param_1[2] = param_1[2] + *(int *)(local_18[0] + 0xc);
          *(undefined2 *)(param_1 + 4) = *(undefined2 *)(iVar1 + (uint)*(ushort *)(param_1 + 4) * 2)
          ;
        } while ((4 < *(ushort *)(param_1 + 4)) &&
                (*(ushort *)(param_1 + 4) < *(ushort *)(local_18[0] + 0x10)));
        iVar1 = FUN_8025ee80(local_18[0],0xfffffffa);
      }
      else {
        iVar1 = FUN_8025ee80(local_18[0],0xfffffff5);
      }
    }
  }
  return iVar1;
}

