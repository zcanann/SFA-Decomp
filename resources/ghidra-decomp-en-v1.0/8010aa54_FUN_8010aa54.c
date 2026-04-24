// Function: FUN_8010aa54
// Entry: 8010aa54
// Size: 500 bytes

void FUN_8010aa54(undefined4 param_1,undefined4 param_2,uint param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  puVar4 = (undefined4 *)uVar7;
  *puVar4 = 0xffffffff;
  puVar4[1] = 0xffffffff;
  puVar4[2] = 0xffffffff;
  puVar4[3] = 0xffffffff;
  if (iVar3 != 0) {
    puVar4[1] = *(undefined4 *)(iVar3 + 0x14);
    iVar5 = 0;
    iVar6 = iVar3;
    do {
      if (((-1 < *(int *)(iVar6 + 0x1c)) &&
          (iVar2 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar2 != 0)) &&
         ((*(byte *)(iVar2 + 0x31) == param_3 ||
          ((*(byte *)(iVar2 + 0x32) == param_3 || (*(byte *)(iVar2 + 0x33) == param_3)))))) {
        bVar1 = ((int)*(char *)(iVar3 + 0x1b) & 1 << iVar5) == 0;
        if (bVar1) {
          if (bVar1) {
            puVar4[2] = *(undefined4 *)(iVar6 + 0x1c);
          }
        }
        else {
          *puVar4 = *(undefined4 *)(iVar6 + 0x1c);
        }
      }
      iVar6 = iVar6 + 4;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 5);
    if (((-1 < (int)puVar4[2]) && (iVar3 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar3 != 0)) &&
       ((*(byte *)(iVar3 + 0x31) == param_3 ||
        ((*(byte *)(iVar3 + 0x32) == param_3 || (*(byte *)(iVar3 + 0x33) == param_3)))))) {
      iVar5 = 0;
      iVar6 = iVar3;
      do {
        if ((((-1 < *(int *)(iVar6 + 0x1c)) && (((int)*(char *)(iVar3 + 0x1b) & 1 << iVar5) == 0))
            && (iVar2 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar2 != 0)) &&
           (((*(byte *)(iVar2 + 0x31) == param_3 || (*(byte *)(iVar2 + 0x32) == param_3)) ||
            (*(byte *)(iVar2 + 0x33) == param_3)))) {
          puVar4[3] = *(undefined4 *)(iVar6 + 0x1c);
        }
        iVar6 = iVar6 + 4;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 5);
    }
    if (((int)puVar4[1] < 0) || ((int)puVar4[2] < 0)) {
      FUN_801378a8(s_PATHCAM_error__need_at_least_two_80319cb4);
    }
  }
  FUN_80286128();
  return;
}

