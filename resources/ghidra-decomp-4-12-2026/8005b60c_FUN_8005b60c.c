// Function: FUN_8005b60c
// Entry: 8005b60c
// Size: 220 bytes

int FUN_8005b60c(int param_1,int *param_2,int *param_3,int *param_4,uint *param_5)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  
  iVar5 = 0;
  piVar3 = &DAT_803870c8;
  iVar8 = 0x78;
  do {
    iVar2 = *piVar3;
    if (iVar2 != 0) {
      iVar7 = *(int *)(iVar2 + 0x20);
      iVar4 = 0;
      for (iVar6 = 0; DAT_803ddb20 = iVar2, iVar6 < (int)(uint)*(ushort *)(iVar2 + 8);
          iVar6 = iVar6 + iVar1) {
        if (*(int *)(iVar7 + 0x14) == param_1) {
          if (param_2 != (int *)0x0) {
            *param_2 = iVar4;
          }
          if (param_3 != (int *)0x0) {
            *param_3 = iVar5;
          }
          if (param_4 != (int *)0x0) {
            *param_4 = (int)*(char *)(DAT_803ddb20 + 0x19);
          }
          if (param_5 == (uint *)0x0) {
            return iVar7;
          }
          *param_5 = (uint)(0x4f < iVar5);
          return iVar7;
        }
        iVar1 = (uint)*(byte *)(iVar7 + 2) * 4;
        iVar7 = iVar7 + iVar1;
        iVar4 = iVar4 + 1;
      }
    }
    piVar3 = piVar3 + 1;
    iVar5 = iVar5 + 1;
    iVar8 = iVar8 + -1;
    if (iVar8 == 0) {
      return 0;
    }
  } while( true );
}

