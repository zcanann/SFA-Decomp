// Function: FUN_8009f164
// Entry: 8009f164
// Size: 260 bytes

void FUN_8009f164(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  undefined2 *puVar6;
  char *pcVar7;
  int *piVar8;
  int *piVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  
  iVar1 = FUN_80286828();
  if (iVar1 != 0) {
    iVar4 = 0;
    piVar9 = &DAT_8039c9b8;
    piVar8 = &DAT_8039c688;
    pcVar7 = &DAT_8039c828;
    puVar6 = &DAT_80310488;
    puVar5 = &DAT_80310528;
    uVar10 = extraout_f1;
    do {
      iVar3 = *piVar9;
      if (iVar1 == *piVar8) {
        iVar2 = 0;
        do {
          if ((iVar3 != 0) && ((&DAT_8039c138)[(uint)(*(byte *)(iVar3 + 0x8a) >> 1) * 4] == iVar1))
          {
            uVar10 = FUN_8009b36c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  *piVar9,iVar4,iVar2,0,1,in_r8,in_r9,in_r10);
          }
          iVar3 = iVar3 + 0xa0;
          if (*pcVar7 == '\0') {
            *puVar6 = 0xffff;
          }
          iVar2 = iVar2 + 1;
        } while (iVar2 < 0x19);
        *piVar8 = 0;
        *puVar5 = 0;
      }
      piVar9 = piVar9 + 1;
      piVar8 = piVar8 + 1;
      pcVar7 = pcVar7 + 1;
      puVar6 = puVar6 + 1;
      puVar5 = puVar5 + 1;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x50);
  }
  FUN_80286874();
  return;
}

