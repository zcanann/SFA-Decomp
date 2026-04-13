// Function: FUN_8028e344
// Entry: 8028e344
// Size: 420 bytes

void FUN_8028e344(double param_1,int param_2,char *param_3)

{
  byte bVar1;
  int iVar2;
  char *pcVar3;
  byte *pbVar4;
  int iVar5;
  short sVar6;
  
  sVar6 = *(short *)(param_2 + 2);
  FUN_8028e4e8(param_1,param_3);
  if ((byte)param_3[5] < 10) {
    if (0x24 < sVar6) {
      sVar6 = 0x24;
    }
    iVar5 = (int)sVar6;
    if ((0 < iVar5) && (iVar5 < (int)(uint)(byte)param_3[4])) {
      if ((byte)param_3[iVar5 + 5] < 6) {
        if ((byte)param_3[iVar5 + 5] < 5) {
          iVar2 = -1;
        }
        else {
          pcVar3 = param_3 + iVar5 + 6;
          iVar2 = (int)(param_3 + (byte)param_3[4] + 5) - (int)pcVar3;
          if (pcVar3 < param_3 + (byte)param_3[4] + 5) {
            do {
              if (*pcVar3 != '\0') {
                iVar2 = 1;
                goto LAB_8028e410;
              }
              pcVar3 = pcVar3 + 1;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
          }
          if ((param_3[iVar5 + 4] & 1U) == 0) {
            iVar2 = -1;
          }
          else {
            iVar2 = 1;
          }
        }
      }
      else {
        iVar2 = 1;
      }
LAB_8028e410:
      param_3[4] = (char)sVar6;
      if (-1 < iVar2) {
        for (pbVar4 = (byte *)(param_3 + 5 + iVar5 + -1); 8 < *pbVar4; pbVar4 = pbVar4 + -1) {
          if (pbVar4 == (byte *)(param_3 + 5)) {
            *pbVar4 = 1;
            *(short *)(param_3 + 2) = *(short *)(param_3 + 2) + 1;
            goto LAB_8028e48c;
          }
          *pbVar4 = 0;
        }
        *pbVar4 = *pbVar4 + 1;
      }
    }
LAB_8028e48c:
    while ((int)(uint)(byte)param_3[4] < iVar5) {
      bVar1 = param_3[4];
      param_3[4] = bVar1 + 1;
      param_3[bVar1 + 5] = '\0';
    }
    *(ushort *)(param_3 + 2) = *(short *)(param_3 + 2) - ((byte)param_3[4] - 1);
    for (iVar5 = 0; iVar5 < (int)(uint)(byte)param_3[4]; iVar5 = iVar5 + 1) {
      param_3[iVar5 + 5] = param_3[iVar5 + 5] + '0';
    }
  }
  return;
}

