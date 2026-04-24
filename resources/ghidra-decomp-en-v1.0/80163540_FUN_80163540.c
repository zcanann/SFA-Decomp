// Function: FUN_80163540
// Entry: 80163540
// Size: 432 bytes

void FUN_80163540(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  char cVar7;
  byte bVar8;
  int iVar9;
  double dVar10;
  int local_38;
  undefined auStack52 [4];
  undefined auStack48 [16];
  longlong local_20;
  
  iVar3 = FUN_802860dc();
  iVar9 = *(int *)(iVar3 + 0xb8);
  iVar4 = FUN_8002b9ec();
  iVar5 = FUN_80037a68(iVar3,&DAT_803dda80,&local_38,auStack48);
  if ((iVar5 != 0) && (*(short *)(local_38 + 0x46) != 0x4ba)) {
    FUN_80096f9c(auStack48,8,0xff,0xff,0x78);
    FUN_8000bb18(iVar3,0x280);
    for (bVar8 = 0; bVar8 < *(byte *)(iVar9 + 0x50); bVar8 = bVar8 + 1) {
      iVar5 = (uint)bVar8 * 4 + 0xc;
      if ((*(int *)(iVar9 + iVar5) != 0) &&
         ((*(short *)(iVar3 + 0x46) != 0x28d ||
          (iVar6 = (**(code **)(*DAT_803dca58 + 0x24))(auStack52), iVar6 != 0)))) {
        (**(code **)(**(int **)(*(int *)(iVar9 + iVar5) + 0x68) + 0x28))();
      }
    }
  }
  fVar1 = *(float *)(iVar3 + 0xc) - *(float *)(iVar4 + 0xc);
  fVar2 = *(float *)(iVar3 + 0x14) - *(float *)(iVar4 + 0x14);
  dVar10 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
  local_20 = (longlong)(int)dVar10;
  if (((int)dVar10 & 0xffffU) < (uint)*(ushort *)(iVar9 + 8)) {
    do {
      cVar7 = FUN_801631c8(iVar3);
    } while (cVar7 != -1);
  }
  for (bVar8 = 0; bVar8 < *(byte *)(iVar9 + 0x50); bVar8 = bVar8 + 1) {
    iVar4 = (uint)bVar8 * 4 + 0xc;
    iVar3 = *(int *)(iVar9 + iVar4);
    if ((iVar3 != 0) && (iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(), 1 < iVar3)) {
      *(undefined4 *)(iVar9 + iVar4) = 0;
    }
  }
  FUN_80286128();
  return;
}

