// Function: FUN_8003ba50
// Entry: 8003ba50
// Size: 540 bytes

void FUN_8003ba50(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,undefined4 param_6)

{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  code *pcVar4;
  int iVar5;
  char cVar7;
  int iVar6;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  uVar2 = (undefined4)((ulonglong)uVar8 >> 0x20);
  if (((((*(ushort *)(param_5 + 0xb0) & 0x40) == 0) && (*(int *)(param_5 + 0xc4) == 0)) &&
      ((*(ushort *)(param_5 + 6) & 0x4000) == 0)) &&
     ((*(int *)(param_5 + 0x30) == 0 || ((*(ushort *)(*(int *)(param_5 + 0x30) + 6) & 0x4000) == 0))
     )) {
    FUN_8002a6b0();
    *(ushort *)(param_5 + 0xb0) = *(ushort *)(param_5 + 0xb0) | 0x800;
    cVar7 = (char)param_6;
    if (*(int **)(param_5 + 0x68) == (int *)0x0) {
      if (cVar7 != '\0') {
        sVar1 = *(short *)(param_5 + 0x46);
        if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
          FUN_802b5830(param_5,uVar2,(int)uVar8,param_3,param_4,cVar7);
        }
        else if ((*(int *)(*(int *)(param_5 + 0x7c) + *(char *)(param_5 + 0xad) * 4) != 0) &&
                (FUN_80041bbc(param_5), *(int *)(param_5 + 0x74) != 0)) {
          FUN_80041110();
        }
      }
    }
    else if ((*(ushort *)(param_5 + 0xb0) & 0x4000) == 0) {
      pcVar4 = *(code **)(**(int **)(param_5 + 0x68) + 0x10);
      if (pcVar4 != (code *)0x0) {
        (*pcVar4)(param_5,uVar2,(int)uVar8,param_3,param_4,param_6);
      }
    }
    else if (((cVar7 != '\0') &&
             (*(int *)(*(int *)(param_5 + 0x7c) + *(char *)(param_5 + 0xad) * 4) != 0)) &&
            (FUN_80041bbc(param_5), *(int *)(param_5 + 0x74) != 0)) {
      FUN_80041110();
    }
    FUN_8002a6ac();
    iVar5 = param_5;
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_5 + 0xeb); iVar6 = iVar6 + 1) {
      iVar3 = *(int *)(iVar5 + 200);
      if (*(short *)(iVar3 + 0x44) == 0x2d) {
        FUN_8003b718(iVar3,param_5,*(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4));
      }
      iVar5 = iVar5 + 4;
    }
  }
  FUN_80286888();
  return;
}

