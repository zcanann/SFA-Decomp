// Function: FUN_8028dbe4
// Entry: 8028dbe4
// Size: 420 bytes

void FUN_8028dbe4(int param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  byte *pbVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  
  sVar8 = *(short *)(param_1 + 2);
  FUN_8028dd88(param_2);
  if (*(byte *)(param_2 + 5) < 10) {
    if (0x24 < sVar8) {
      sVar8 = 0x24;
    }
    iVar7 = (int)sVar8;
    if ((0 < iVar7) && (iVar7 < (int)(uint)*(byte *)(param_2 + 4))) {
      iVar6 = param_2 + iVar7;
      if (*(byte *)(iVar6 + 5) < 6) {
        if (*(byte *)(iVar6 + 5) < 5) {
          iVar6 = -1;
        }
        else {
          pcVar4 = (char *)(iVar6 + 6);
          pcVar3 = (char *)(param_2 + *(byte *)(param_2 + 4) + 5);
          iVar2 = (int)pcVar3 - (int)pcVar4;
          if (pcVar4 < pcVar3) {
            do {
              if (*pcVar4 != '\0') {
                iVar6 = 1;
                goto LAB_8028dcb0;
              }
              pcVar4 = pcVar4 + 1;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
          }
          if ((*(byte *)(iVar6 + 4) & 1) == 0) {
            iVar6 = -1;
          }
          else {
            iVar6 = 1;
          }
        }
      }
      else {
        iVar6 = 1;
      }
LAB_8028dcb0:
      *(char *)(param_2 + 4) = (char)sVar8;
      if (-1 < iVar6) {
        for (pbVar5 = (byte *)(param_2 + 5) + iVar7 + -1; 8 < *pbVar5; pbVar5 = pbVar5 + -1) {
          if (pbVar5 == (byte *)(param_2 + 5)) {
            *pbVar5 = 1;
            *(short *)(param_2 + 2) = *(short *)(param_2 + 2) + 1;
            goto LAB_8028dd2c;
          }
          *pbVar5 = 0;
        }
        *pbVar5 = *pbVar5 + 1;
      }
    }
LAB_8028dd2c:
    while ((int)(uint)*(byte *)(param_2 + 4) < iVar7) {
      bVar1 = *(byte *)(param_2 + 4);
      *(byte *)(param_2 + 4) = bVar1 + 1;
      *(undefined *)(param_2 + bVar1 + 5) = 0;
    }
    *(ushort *)(param_2 + 2) = *(short *)(param_2 + 2) - (*(byte *)(param_2 + 4) - 1);
    for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_2 + 4); iVar7 = iVar7 + 1) {
      *(char *)(param_2 + iVar7 + 5) = *(char *)(param_2 + iVar7 + 5) + '0';
    }
  }
  return;
}

