// Function: FUN_8020fb2c
// Entry: 8020fb2c
// Size: 644 bytes

void FUN_8020fb2c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined uVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined8 uVar7;
  float local_40 [2];
  undefined4 local_38;
  uint uStack52;
  
  uVar7 = FUN_802860cc();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  local_40[0] = FLOAT_803e6708;
  piVar6 = *(int **)(iVar3 + 0xb8);
  iVar5 = *piVar6;
  if (*(byte *)(iVar3 + 0x36) < 5) {
    piVar6[0x2b] = (int)FLOAT_803e66f0;
  }
  bVar2 = false;
  if (((-1 < *(char *)(piVar6 + 0x29)) && (iVar5 != 0)) &&
     (iVar4 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x38))(iVar5), iVar4 == 2)) {
    bVar2 = true;
  }
  if (bVar2) {
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 8;
    param_6 = FUN_8005a194(iVar5);
    FUN_8020f594(iVar3,iVar5,(int)uVar7,param_3,param_4,param_5,(int)param_6,
                 *(undefined *)(piVar6 + 0x28),1);
  }
  else {
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xfff7;
  }
  if ((param_6 != '\0') && (*(char *)(piVar6 + 0x28) != '\0')) {
    uVar1 = *(undefined *)(iVar3 + 0x37);
    if (bVar2) {
      *(char *)(iVar3 + 0x37) = *(char *)(piVar6 + 0x28);
    }
    if (((*(char *)(iVar3 + 0xeb) == '\0') && (*(short *)(iVar3 + 0x46) == 0x389)) &&
       ((*(char *)((int)piVar6 + 0xaa) < '\0' &&
        (((iVar5 = FUN_80036e58(0x1e,iVar3,local_40), iVar5 != 0 &&
          (iVar4 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x24))(), iVar4 != 0)) &&
         (iVar4 = (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5,0), iVar4 != 0)))))) {
      FUN_80037d2c(iVar3,iVar5,0);
    }
    FUN_8003b8f4((double)FLOAT_803e670c,iVar3,(int)uVar7,param_3,param_4,param_5);
    FUN_8003842c(iVar3,1,piVar6 + 6,piVar6 + 7,piVar6 + 8,0);
    *(undefined *)(iVar3 + 0x37) = uVar1;
    if ((*(byte *)((int)piVar6 + 0xaa) >> 6 & 1) != 0) {
      if ((float)piVar6[0x2b] == FLOAT_803e66f0) {
        *(byte *)((int)piVar6 + 0xaa) = *(byte *)((int)piVar6 + 0xaa) & 0xbf;
      }
      else {
        uStack52 = 0xff - *(byte *)(iVar3 + 0x36) ^ 0x80000000;
        local_38 = 0x43300000;
        piVar6[0x2b] = (int)(FLOAT_803e670c +
                            (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e6718) /
                            FLOAT_803e6710);
      }
      FUN_80099d84((double)FLOAT_803e670c,(double)(float)piVar6[0x2b],iVar3,3,0);
    }
  }
  FUN_80286118();
  return;
}

