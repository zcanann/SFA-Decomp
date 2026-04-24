// Function: FUN_801adbac
// Entry: 801adbac
// Size: 380 bytes

void FUN_801adbac(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined uVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860cc();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  if (*(short *)(iVar3 + 0x46) == 0x373) {
    FUN_8003b8f4((double)FLOAT_803e4758);
  }
  else {
    iVar4 = FUN_8001ffb4(0x6e);
    if ((iVar4 == 0) || (iVar4 = FUN_8001ffb4(0x382), iVar4 != 0)) {
      piVar6 = *(int **)(iVar3 + 0xb8);
      iVar4 = *piVar6;
      bVar2 = false;
      if ((iVar4 != 0) &&
         (iVar5 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x38))(iVar4), iVar5 == 2)) {
        bVar2 = true;
      }
      if (bVar2) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 8;
        param_6 = FUN_8005a194(iVar4);
        FUN_801ad7e4(iVar3,iVar4,(int)uVar7,param_3,param_4,param_5,(int)param_6,
                     *(undefined *)(piVar6 + 8),1);
      }
      else {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xfff7;
      }
      if ((param_6 != '\0') && (*(char *)(piVar6 + 8) != '\0')) {
        uVar1 = *(undefined *)(iVar3 + 0x37);
        if (bVar2) {
          *(char *)(iVar3 + 0x37) = *(char *)(piVar6 + 8);
        }
        FUN_8003b8f4((double)FLOAT_803e4758,iVar3,(int)uVar7,param_3,param_4,param_5);
        FUN_8003842c(iVar3,1,piVar6 + 5,piVar6 + 6,piVar6 + 7,0);
        *(undefined *)(iVar3 + 0x37) = uVar1;
      }
    }
  }
  FUN_80286118();
  return;
}

