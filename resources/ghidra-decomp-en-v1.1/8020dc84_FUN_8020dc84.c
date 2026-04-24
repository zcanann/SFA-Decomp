// Function: FUN_8020dc84
// Entry: 8020dc84
// Size: 480 bytes

void FUN_8020dc84(undefined4 param_1,undefined4 param_2,undefined *param_3)

{
  char cVar2;
  char cVar3;
  int iVar1;
  undefined uVar4;
  undefined uVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286838();
  iVar6 = *(int *)((int)((ulonglong)uVar7 >> 0x20) + 0xb8);
  cVar2 = FUN_80014cec(0);
  cVar3 = FUN_80014c98(0);
  uVar5 = 0;
  uVar4 = 0;
  iVar1 = FUN_800431a4();
  if (iVar1 == 0) {
    if ((cVar2 < -0x23) && (-0x24 < *(char *)(iVar6 + 10))) {
      uVar5 = 0xff;
      *(undefined *)(iVar6 + 0xc) = 0;
    }
    if (('#' < cVar2) && (*(char *)(iVar6 + 10) < '$')) {
      uVar5 = 1;
      *(undefined *)(iVar6 + 0xc) = 0;
    }
    if ((cVar3 < -0x23) && (-0x24 < *(char *)(iVar6 + 0xb))) {
      uVar4 = 0xff;
      *(undefined *)(iVar6 + 0xd) = 0;
    }
    if (('#' < cVar3) && (*(char *)(iVar6 + 0xb) < '$')) {
      uVar4 = 1;
      *(undefined *)(iVar6 + 0xd) = 0;
    }
    *(char *)(iVar6 + 0xb) = cVar3;
    if (*(char *)(iVar6 + 0xb) < -0x23) {
      *(char *)(iVar6 + 0xd) = *(char *)(iVar6 + 0xd) + '\x01';
    }
    else if (*(char *)(iVar6 + 0xb) < '$') {
      *(undefined *)(iVar6 + 0xd) = 0;
    }
    else {
      *(char *)(iVar6 + 0xd) = *(char *)(iVar6 + 0xd) + '\x01';
    }
    if ('2' < *(char *)(iVar6 + 0xd)) {
      *(undefined *)(iVar6 + 0xb) = 0;
      *(undefined *)(iVar6 + 0xd) = 0;
    }
    *(char *)(iVar6 + 10) = cVar2;
    if (*(char *)(iVar6 + 10) < -0x23) {
      *(char *)(iVar6 + 0xc) = *(char *)(iVar6 + 0xc) + '\x01';
    }
    else if (*(char *)(iVar6 + 10) < '$') {
      *(undefined *)(iVar6 + 0xc) = 0;
    }
    else {
      *(char *)(iVar6 + 0xc) = *(char *)(iVar6 + 0xc) + '\x01';
    }
    if ('2' < *(char *)(iVar6 + 0xc)) {
      *(undefined *)(iVar6 + 10) = 0;
      *(undefined *)(iVar6 + 0xc) = 0;
    }
    *(undefined *)uVar7 = uVar5;
    *param_3 = uVar4;
  }
  else {
    *(undefined *)uVar7 = 0;
    *param_3 = 0;
  }
  FUN_80286884();
  return;
}

