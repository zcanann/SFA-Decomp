// Function: FUN_80200088
// Entry: 80200088
// Size: 572 bytes

void FUN_80200088(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  int **ppiVar8;
  undefined8 uVar9;
  float local_28;
  undefined auStack36 [36];
  
  uVar9 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar7 = *(int *)(iVar1 + 0x4c);
  local_28 = FLOAT_803e62ac;
  ppiVar8 = *(int ***)(*(int *)(iVar1 + 0xb8) + 0x40c);
  if ((*(char *)(iVar5 + 0x27b) == '\0') && ((*(byte *)(ppiVar8 + 0x11) >> 6 & 1) == 0)) {
    if ((ppiVar8[6] == (int *)0x0) && (FLOAT_803e62b0 < (float)ppiVar8[0xe])) {
      ppiVar8[0xe] = (int *)((float)ppiVar8[0xe] - FLOAT_803e62b0);
      local_28 = FLOAT_803e62b4;
      iVar2 = 3;
      puVar6 = (undefined4 *)0x80329708;
      iVar7 = 0;
      while( true ) {
        puVar6 = puVar6 + -1;
        iVar2 = iVar2 + -1;
        if (iVar2 < 0) break;
        iVar4 = FUN_80036d60(*puVar6,iVar1,&local_28);
        if (iVar4 != 0) {
          iVar7 = iVar4;
        }
      }
      *(int *)(iVar5 + 0x2d0) = iVar7;
      if (iVar7 != 0) {
        if (FLOAT_803e62b8 <= local_28) {
          (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar5,4);
        }
        else {
          (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar5,2);
        }
      }
    }
  }
  else {
    *(byte *)((int)ppiVar8 + 0x15) = *(byte *)((int)ppiVar8 + 0x15) & 0xfb;
    *(byte *)(ppiVar8 + 0x11) = *(byte *)(ppiVar8 + 0x11) & 0xbf;
    iVar2 = FUN_800138b4(ppiVar8[9]);
    if (iVar2 == 0) {
      FUN_800138e0(ppiVar8[9],auStack36);
    }
    iVar2 = (int)ppiVar8[8] - **ppiVar8;
    iVar2 = iVar2 / 0xc + (iVar2 >> 0x1f);
    if ((int)*(short *)(*ppiVar8 + 1) <= iVar2 - (iVar2 >> 0x1f)) {
      ppiVar8[8] = (int *)0x0;
    }
    if (ppiVar8[8] == (int *)0x0) {
      ppiVar8[8] = (int *)**ppiVar8;
      *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar7 + 0x10);
    }
    if (ppiVar8[8][1] != 0) {
      uVar3 = FUN_80036d60(ppiVar8[8][1],iVar1,&local_28);
      *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
    }
    if (*(int *)(iVar5 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dca8c + 0x14))(iVar1,iVar5,*ppiVar8[8]);
    }
  }
  FUN_80286128(0);
  return;
}

