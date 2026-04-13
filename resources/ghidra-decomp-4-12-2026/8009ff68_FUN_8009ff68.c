// Function: FUN_8009ff68
// Entry: 8009ff68
// Size: 416 bytes

void FUN_8009ff68(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined *puVar1;
  undefined4 *puVar2;
  undefined *puVar3;
  undefined2 *puVar4;
  undefined *puVar5;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  
  piVar7 = &DAT_8039b7b8;
  FUN_8009b4e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  puVar2 = &DAT_8039c878;
  puVar3 = &DAT_8039c828;
  puVar4 = &DAT_80310488;
  puVar1 = &DAT_80310528;
  puVar5 = &DAT_8039c638;
  puVar6 = &DAT_8039c688;
  iVar8 = 10;
  do {
    *puVar2 = 0;
    *puVar3 = 0;
    *puVar4 = 0xffff;
    *puVar1 = 0;
    *puVar5 = 0;
    *puVar6 = 0;
    puVar2[1] = 0;
    puVar3[1] = 0;
    puVar4[1] = 0xffff;
    puVar1[1] = 0;
    puVar5[1] = 0;
    puVar6[1] = 0;
    puVar2[2] = 0;
    puVar3[2] = 0;
    puVar4[2] = 0xffff;
    puVar1[2] = 0;
    puVar5[2] = 0;
    puVar6[2] = 0;
    puVar2[3] = 0;
    puVar3[3] = 0;
    puVar4[3] = 0xffff;
    puVar1[3] = 0;
    puVar5[3] = 0;
    puVar6[3] = 0;
    puVar2[4] = 0;
    puVar3[4] = 0;
    puVar4[4] = 0xffff;
    puVar1[4] = 0;
    puVar5[4] = 0;
    puVar6[4] = 0;
    puVar2[5] = 0;
    puVar3[5] = 0;
    puVar4[5] = 0xffff;
    puVar1[5] = 0;
    puVar5[5] = 0;
    puVar6[5] = 0;
    puVar2[6] = 0;
    puVar3[6] = 0;
    puVar4[6] = 0xffff;
    puVar1[6] = 0;
    puVar5[6] = 0;
    puVar6[6] = 0;
    puVar2[7] = 0;
    puVar3[7] = 0;
    puVar4[7] = 0xffff;
    puVar1[7] = 0;
    puVar5[7] = 0;
    puVar6[7] = 0;
    puVar2 = puVar2 + 8;
    puVar3 = puVar3 + 8;
    puVar4 = puVar4 + 8;
    puVar1 = puVar1 + 8;
    puVar5 = puVar5 + 8;
    puVar6 = puVar6 + 8;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  DAT_8039c7cc = 0;
  DAT_8039c7c8 = 0;
  DAT_8039c7d4 = 0;
  DAT_8039c7d0 = 0;
  DAT_803dded8 = 1;
  iVar8 = 0;
  do {
    if (*piVar7 != 0) {
      FUN_80054484();
    }
    *piVar7 = 0;
    piVar7[2] = 0;
    piVar7[1] = 0;
    piVar7[3] = 0;
    piVar7 = piVar7 + 4;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 0x20);
  DAT_803dded8 = 0;
  return;
}

