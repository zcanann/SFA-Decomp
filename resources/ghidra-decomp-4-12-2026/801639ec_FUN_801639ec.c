// Function: FUN_801639ec
// Entry: 801639ec
// Size: 432 bytes

void FUN_801639ec(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  byte bVar7;
  int iVar8;
  double dVar9;
  double extraout_f1;
  double dVar10;
  int local_38;
  undefined auStack_34 [4];
  float afStack_30 [4];
  longlong local_20;
  
  uVar2 = FUN_80286840();
  iVar8 = *(int *)(uVar2 + 0xb8);
  iVar3 = FUN_8002bac4();
  iVar4 = FUN_80037b60(uVar2,(float *)&DAT_803de700,&local_38,afStack_30);
  if ((iVar4 != 0) && (*(short *)(local_38 + 0x46) != 0x4ba)) {
    FUN_80097228(afStack_30,8,0xff,0xff,0x78);
    FUN_8000bb38(uVar2,0x280);
    for (bVar7 = 0; bVar7 < *(byte *)(iVar8 + 0x50); bVar7 = bVar7 + 1) {
      iVar4 = (uint)bVar7 * 4 + 0xc;
      if ((*(int *)(iVar8 + iVar4) != 0) &&
         ((*(short *)(uVar2 + 0x46) != 0x28d ||
          (iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_34), iVar5 != 0)))) {
        (**(code **)(**(int **)(*(int *)(iVar8 + iVar4) + 0x68) + 0x28))();
      }
    }
  }
  dVar10 = (double)(*(float *)(uVar2 + 0xc) - *(float *)(iVar3 + 0xc));
  fVar1 = *(float *)(uVar2 + 0x14) - *(float *)(iVar3 + 0x14);
  dVar9 = FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(fVar1 * fVar1)));
  local_20 = (longlong)(int)dVar9;
  if (((int)dVar9 & 0xffffU) < (uint)*(ushort *)(iVar8 + 8)) {
    do {
      cVar6 = FUN_80163674(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8);
      dVar9 = extraout_f1;
    } while (cVar6 != -1);
  }
  for (bVar7 = 0; bVar7 < *(byte *)(iVar8 + 0x50); bVar7 = bVar7 + 1) {
    iVar4 = (uint)bVar7 * 4 + 0xc;
    iVar3 = *(int *)(iVar8 + iVar4);
    if ((iVar3 != 0) && (iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(), 1 < iVar3)) {
      *(undefined4 *)(iVar8 + iVar4) = 0;
    }
  }
  FUN_8028688c();
  return;
}

