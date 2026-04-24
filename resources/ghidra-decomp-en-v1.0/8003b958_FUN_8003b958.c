// Function: FUN_8003b958
// Entry: 8003b958
// Size: 540 bytes

void FUN_8003b958(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,undefined4 param_6)

{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  code *pcVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860d8();
  uVar2 = (undefined4)((ulonglong)uVar8 >> 0x20);
  uVar4 = (undefined4)uVar8;
  if (((((*(ushort *)(param_5 + 0xb0) & 0x40) == 0) && (*(int *)(param_5 + 0xc4) == 0)) &&
      ((*(ushort *)(param_5 + 6) & 0x4000) == 0)) &&
     ((*(int *)(param_5 + 0x30) == 0 || ((*(ushort *)(*(int *)(param_5 + 0x30) + 6) & 0x4000) == 0))
     )) {
    FUN_8002a5d8(4);
    *(ushort *)(param_5 + 0xb0) = *(ushort *)(param_5 + 0xb0) | 0x800;
    if (*(int **)(param_5 + 0x68) == (int *)0x0) {
      if ((char)param_6 != '\0') {
        sVar1 = *(short *)(param_5 + 0x46);
        if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
          FUN_802b50d0(param_5,uVar2,uVar4,param_3,param_4,param_6);
        }
        else if ((*(int *)(*(int *)(param_5 + 0x7c) + *(char *)(param_5 + 0xad) * 4) != 0) &&
                (FUN_80041ac4(param_5), *(int *)(param_5 + 0x74) != 0)) {
          FUN_80041018(param_5);
        }
      }
    }
    else if ((*(ushort *)(param_5 + 0xb0) & 0x4000) == 0) {
      pcVar5 = *(code **)(**(int **)(param_5 + 0x68) + 0x10);
      if (pcVar5 != (code *)0x0) {
        (*pcVar5)(param_5,uVar2,uVar4,param_3,param_4,param_6);
      }
    }
    else if ((((char)param_6 != '\0') &&
             (*(int *)(*(int *)(param_5 + 0x7c) + *(char *)(param_5 + 0xad) * 4) != 0)) &&
            (FUN_80041ac4(param_5), *(int *)(param_5 + 0x74) != 0)) {
      FUN_80041018(param_5);
    }
    FUN_8002a5d4();
    iVar6 = param_5;
    for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_5 + 0xeb); iVar7 = iVar7 + 1) {
      iVar3 = *(int *)(iVar6 + 200);
      if (*(short *)(iVar3 + 0x44) == 0x2d) {
        FUN_8003b620(iVar3,param_5,
                     *(undefined4 *)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4),uVar2,
                     uVar4,param_3);
      }
      iVar6 = iVar6 + 4;
    }
  }
  FUN_80286124();
  return;
}

