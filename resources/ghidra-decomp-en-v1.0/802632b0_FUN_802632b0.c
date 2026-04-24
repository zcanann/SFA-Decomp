// Function: FUN_802632b0
// Entry: 802632b0
// Size: 544 bytes

int FUN_802632b0(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 *param_4,
                undefined *param_5)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  ushort uVar4;
  char *pcVar5;
  ushort uVar6;
  int local_2c [2];
  
  uVar1 = FUN_802918a4(param_2);
  if (uVar1 < 0x21) {
    iVar2 = FUN_8025edc8(param_1,local_2c);
    if (-1 < iVar2) {
      if ((param_3 == 0) ||
         (param_3 != (param_3 / *(uint *)(local_2c[0] + 0xc)) * *(uint *)(local_2c[0] + 0xc))) {
        iVar2 = -0x80;
      }
      else {
        uVar6 = 0xffff;
        pcVar3 = (char *)FUN_802608b0();
        pcVar5 = pcVar3;
        for (uVar4 = 0; uVar4 < 0x7f; uVar4 = uVar4 + 1) {
          if (*pcVar5 == -1) {
            if (uVar6 == 0xffff) {
              uVar6 = uVar4;
            }
          }
          else {
            iVar2 = FUN_8028f228(pcVar5,*(undefined4 *)(local_2c[0] + 0x10c),4);
            if (((iVar2 == 0) &&
                (iVar2 = FUN_8028f228(pcVar5 + 4,*(int *)(local_2c[0] + 0x10c) + 4,2), iVar2 == 0))
               && (iVar2 = FUN_80262d2c(pcVar5,param_2), iVar2 != 0)) {
              iVar2 = FUN_8025ee80(local_2c[0],0xfffffff9);
              return iVar2;
            }
          }
          pcVar5 = pcVar5 + 0x40;
        }
        if (uVar6 == 0xffff) {
          iVar2 = FUN_8025ee80(local_2c[0],0xfffffff8);
        }
        else {
          iVar2 = FUN_802604ac(local_2c[0]);
          if (*(int *)(local_2c[0] + 0xc) * (uint)*(ushort *)(iVar2 + 6) < param_3) {
            iVar2 = FUN_8025ee80(local_2c[0],0xfffffff7);
          }
          else {
            if (param_5 == (undefined *)0x0) {
              param_5 = &DAT_8025de80;
            }
            *(undefined **)(local_2c[0] + 0xd0) = param_5;
            *(ushort *)(local_2c[0] + 0xbc) = uVar6;
            *(short *)(pcVar3 + (uint)uVar6 * 0x40 + 0x38) =
                 (short)(param_3 / *(uint *)(local_2c[0] + 0xc));
            FUN_802917a8(pcVar3 + (uint)uVar6 * 0x40 + 8,param_2,0x20);
            *(undefined4 **)(local_2c[0] + 0xc0) = param_4;
            *param_4 = param_1;
            param_4[1] = (uint)uVar6;
            iVar2 = FUN_80260650(param_1,param_3 / *(uint *)(local_2c[0] + 0xc),&LAB_80263180);
            if (iVar2 < 0) {
              iVar2 = FUN_8025ee80(local_2c[0]);
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

