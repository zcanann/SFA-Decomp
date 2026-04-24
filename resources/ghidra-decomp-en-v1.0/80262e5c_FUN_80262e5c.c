// Function: FUN_80262e5c
// Entry: 80262e5c
// Size: 336 bytes

undefined4 FUN_80262e5c(int *param_1,char *param_2,int *param_3)

{
  char cVar1;
  char cVar2;
  bool bVar3;
  int iVar4;
  undefined4 uVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  int iVar9;
  
  if (*param_1 == 0) {
    uVar5 = 0xfffffffd;
  }
  else {
    pcVar6 = (char *)FUN_802608b0(param_1);
    iVar9 = 0;
    do {
      if (*pcVar6 == -1) {
        iVar4 = -4;
      }
      else if (((undefined *)param_1[0x43] == &DAT_803af400) ||
              ((iVar4 = FUN_8028f228(pcVar6,(undefined *)param_1[0x43],4), iVar4 == 0 &&
               (iVar4 = FUN_8028f228(pcVar6 + 4,param_1[0x43] + 4,2), iVar4 == 0)))) {
        iVar4 = 0;
      }
      else {
        iVar4 = -10;
      }
      if (-1 < iVar4) {
        pcVar7 = pcVar6 + 8;
        iVar4 = 0x20;
        pcVar8 = param_2;
        do {
          iVar4 = iVar4 + -1;
          if (iVar4 < 0) {
            if (*pcVar8 == '\0') {
              bVar3 = true;
            }
            else {
              bVar3 = false;
            }
            goto LAB_80262f70;
          }
          cVar1 = *pcVar7;
          pcVar7 = pcVar7 + 1;
          cVar2 = *pcVar8;
          pcVar8 = pcVar8 + 1;
          if (cVar1 != cVar2) {
            bVar3 = false;
            goto LAB_80262f70;
          }
        } while (cVar2 != '\0');
        bVar3 = true;
LAB_80262f70:
        if (bVar3) {
          *param_3 = iVar9;
          return 0;
        }
      }
      iVar9 = iVar9 + 1;
      pcVar6 = pcVar6 + 0x40;
    } while (iVar9 < 0x7f);
    uVar5 = 0xfffffffc;
  }
  return uVar5;
}

