// Function: FUN_80015964
// Entry: 80015964
// Size: 336 bytes

void FUN_80015964(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined uVar5;
  int iVar4;
  int *piVar6;
  undefined4 in_r6;
  int iVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860d4();
  piVar6 = (int *)uVar8;
  if (piVar6 != (int *)0x0) {
    *piVar6 = 0;
  }
  FUN_8024b418(1);
  iVar2 = DAT_803dc954;
  if (DAT_803dc954 == 0) {
    uVar5 = FUN_80022d3c(0);
    iVar2 = FUN_80023cc8(0x3c,0xfacefeed,0);
    FUN_80022d3c(uVar5);
  }
  iVar3 = FUN_80248b9c((int)((ulonglong)uVar8 >> 0x20),iVar2);
  if (iVar3 == 0) {
    FUN_80023800(iVar2);
    iVar3 = 0;
  }
  else {
    iVar7 = *(int *)(iVar2 + 0x34);
    uVar1 = iVar7 + 0x1fU & 0xffffffe0;
    uVar5 = FUN_80022d3c(0);
    iVar3 = FUN_80023cc8(uVar1,0x7d7d7d7d,0);
    FUN_80022d3c(uVar5);
    if (iVar3 == 0) {
      FUN_80023800(iVar2);
      iVar3 = 0;
    }
    else {
      iVar4 = FUN_80248eac(iVar2,iVar3,uVar1,0,in_r6,2);
      if (iVar4 == 0) {
        FUN_80023800(iVar3);
        FUN_80023800(iVar2);
        iVar3 = 0;
      }
      else if (piVar6 != (int *)0x0) {
        *piVar6 = iVar7;
      }
    }
  }
  FUN_80286120(iVar3);
  return;
}

