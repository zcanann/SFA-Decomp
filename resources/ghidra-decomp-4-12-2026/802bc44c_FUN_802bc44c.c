// Function: FUN_802bc44c
// Entry: 802bc44c
// Size: 716 bytes

void FUN_802bc44c(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  short *psVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 local_28 [10];
  
  uVar7 = FUN_80286840();
  psVar2 = (short *)((ulonglong)uVar7 >> 0x20);
  local_28[0] = DAT_803e8ec8;
  *psVar2 = (short)((int)*(char *)((int)uVar7 + 0x18) << 8);
  *(code **)(psVar2 + 0x5e) = FUN_802bb420;
  FUN_800372f8((int)psVar2,10);
  iVar6 = *(int *)(psVar2 + 0x5c);
  *(undefined *)(iVar6 + 0xa8c) = *(undefined *)((int)uVar7 + 0x19);
  *(undefined2 *)(iVar6 + 0xa86) = 5;
  *(undefined2 *)(iVar6 + 0xa88) = 1000;
  iVar3 = *(int *)(psVar2 + 0x32);
  if (iVar3 != 0) {
    *(uint *)(iVar3 + 0x30) = *(uint *)(iVar3 + 0x30) | 0xa10;
  }
  if (*(int *)(psVar2 + 0x2a) != 0) {
    *(undefined2 *)(*(int *)(psVar2 + 0x2a) + 0xb2) = 9;
  }
  (**(code **)(*DAT_803dd70c + 4))(psVar2,iVar6,0xc,1);
  *(float *)(iVar6 + 0x2a4) = FLOAT_803e8f50;
  iVar3 = iVar6 + 4;
  *(undefined *)(iVar6 + 0x25f) = 0;
  bVar1 = *(byte *)(iVar6 + 0xa8c);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 == 0) goto LAB_802bc5dc;
    }
    else if (4 < bVar1) goto LAB_802bc5dc;
    (**(code **)(*DAT_803dd728 + 4))(iVar3,3,0x200020,1);
    (**(code **)(*DAT_803dd728 + 8))(iVar3,2,&DAT_80335d70,&DAT_803dd39c,8);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar3,4,&DAT_80335d30,&DAT_80335d60,local_28);
    (**(code **)(*DAT_803dd728 + 0x20))(psVar2,iVar3);
  }
LAB_802bc5dc:
  FUN_80115200((int)psVar2,(undefined4 *)(iVar6 + 0x35c),0xe000,0x2aaa,3);
  *(byte *)(iVar6 + 0x96d) = *(byte *)(iVar6 + 0x96d) | 8;
  if (param_3 == 0) {
    cVar5 = -1;
    bVar1 = *(byte *)(iVar6 + 0xa8c);
    if (bVar1 == 3) {
      cVar5 = '\x01';
    }
    else if (bVar1 < 3) {
      if ((bVar1 == 1) && (uVar4 = FUN_80020078(0x16f), uVar4 != 0)) {
        cVar5 = '\0';
      }
    }
    else if ((bVar1 < 5) && (uVar4 = FUN_80020078(0x1db), uVar4 != 0)) {
      cVar5 = '\x02';
    }
    if (-1 < cVar5) {
      iVar3 = cVar5 * 0x24;
      uVar4 = FUN_80020078((uint)*(ushort *)(iVar3 + -0x7fcca352));
      if (uVar4 == 0) {
        *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(iVar3 + -0x7fcca370);
        *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(iVar3 + -0x7fcca36c);
        *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(iVar3 + -0x7fcca368);
        *psVar2 = *(short *)(iVar3 + -0x7fcca364);
      }
      else {
        *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(iVar3 + -0x7fcca360);
        *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(iVar3 + -0x7fcca35c);
        *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(iVar3 + -0x7fcca358);
        *psVar2 = *(short *)(iVar3 + -0x7fcca354);
      }
      uVar4 = FUN_80020078((uint)*(ushort *)(iVar3 + -0x7fcca350));
      if (uVar4 != 0) {
        *psVar2 = *psVar2 + -0x8000;
      }
    }
  }
  FUN_8028688c();
  return;
}

