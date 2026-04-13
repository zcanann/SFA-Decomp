// Function: FUN_8001275c
// Entry: 8001275c
// Size: 268 bytes

void FUN_8001275c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  bool bVar2;
  int *piVar3;
  int iVar4;
  short *psVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  byte *in_r8;
  undefined2 *in_r9;
  undefined4 in_r10;
  int iVar6;
  uint uVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar8 = FUN_80286840();
  piVar3 = (int *)((ulonglong)uVar8 >> 0x20);
  bVar2 = false;
  iVar6 = (int)uVar8;
  uVar8 = extraout_f1;
  for (; (!bVar2 && (iVar6 != 0)); iVar6 = iVar6 + -1) {
    iVar4 = piVar3[1];
    if (*(short *)((int)piVar3 + 0x1e) == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      uVar7 = (uint)*(ushort *)(iVar4 + 6);
      *(undefined2 *)(iVar4 + 4) = *(undefined2 *)(iVar4 + *(short *)((int)piVar3 + 0x1e) * 4);
      sVar1 = *(short *)((int)piVar3 + 0x1e);
      *(short *)((int)piVar3 + 0x1e) = sVar1 + -1;
      *(undefined2 *)(iVar4 + 6) = *(undefined2 *)(iVar4 + sVar1 * 4 + 2);
      uVar8 = FUN_80010f8c(iVar4,(int)*(short *)((int)piVar3 + 0x1e),1);
    }
    if ((int)uVar7 < 0) {
      bVar2 = true;
    }
    else {
      psVar5 = (short *)(*piVar3 + uVar7 * 0xe);
      piVar3[6] = uVar7;
      if ((*psVar5 == *(short *)(piVar3 + 3)) && (psVar5[2] == *(short *)(piVar3 + 4))) {
        bVar2 = true;
      }
      else {
        *(undefined *)(psVar5 + 6) = 1;
        uVar8 = FUN_8001190c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar3,
                             psVar5,uVar7,in_r6,in_r7,in_r8,in_r9,in_r10);
      }
    }
  }
  FUN_8028688c();
  return;
}

