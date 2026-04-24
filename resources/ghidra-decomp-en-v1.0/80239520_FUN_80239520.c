// Function: FUN_80239520
// Entry: 80239520
// Size: 600 bytes

void FUN_80239520(void)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int local_28 [2];
  longlong local_20;
  
  iVar2 = FUN_802860dc();
  piVar6 = *(int **)(iVar2 + 0xb8);
  bVar1 = *(byte *)((int)piVar6 + 0x1b) >> 4;
  if (bVar1 == 5) {
    piVar3 = (int *)FUN_80036f50(0x48,local_28);
    iVar5 = 0;
    piVar4 = piVar3;
    iVar7 = local_28[0];
    if (0 < local_28[0]) {
      do {
        if (*(char *)(*(int *)(*piVar4 + 0x4c) + 0x1b) == *(char *)((int)piVar6 + 0x1a)) break;
        piVar4 = piVar4 + 1;
        iVar5 = iVar5 + 1;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    if (iVar5 == local_28[0]) {
      *(byte *)((int)piVar6 + 0x1b) = *(byte *)((int)piVar6 + 0x1b) & 0xf | 0xa0;
    }
    else {
      iVar7 = FUN_8008fb20((double)(float)piVar6[2],(double)(float)piVar6[3],iVar2 + 0xc,
                           piVar3[iVar5] + 0xc,*(undefined *)(piVar6 + 6),
                           *(undefined *)((int)piVar6 + 0x19),0);
      *piVar6 = iVar7;
      *(byte *)((int)piVar6 + 0x1b) = *(byte *)((int)piVar6 + 0x1b) & 0xf | 0x60;
      piVar6[1] = (int)FLOAT_803e7450;
      if ((*(byte *)((int)piVar6 + 0x1b) & 1) != 0) {
        FUN_80097070((double)(float)piVar6[4],iVar2,1,7,0x1e,0);
      }
      iVar7 = *(int *)(piVar3[iVar5] + 0xb8);
      if ((*(byte *)(iVar7 + 0x1b) & 1) != 0) {
        FUN_80097070((double)*(float *)(iVar7 + 0x10),piVar3[iVar5],1,7,0x1e,0);
      }
      if ((*(byte *)((int)piVar6 + 0x1b) & 2) != 0) {
        FUN_800972dc((double)(float)piVar6[5],(double)FLOAT_803e7454,iVar2,5,1,1,100,0,0);
      }
      if ((*(byte *)(iVar7 + 0x1b) & 2) != 0) {
        FUN_800972dc((double)*(float *)(iVar7 + 0x14),(double)FLOAT_803e7454,piVar3[iVar5],5,1,1,100
                     ,0,0);
      }
    }
  }
  else if ((bVar1 == 6) && (*piVar6 != 0)) {
    FUN_8008f904();
    piVar6[1] = (int)((float)piVar6[1] + FLOAT_803db414);
    local_20 = (longlong)(int)(FLOAT_803e7458 + (float)piVar6[1]);
    *(short *)(*piVar6 + 0x20) = (short)(int)(FLOAT_803e7458 + (float)piVar6[1]);
    if (*(ushort *)(*piVar6 + 0x22) <= *(ushort *)(*piVar6 + 0x20)) {
      FUN_80023800();
      *piVar6 = 0;
      *(byte *)((int)piVar6 + 0x1b) = *(byte *)((int)piVar6 + 0x1b) & 0xf;
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
    }
  }
  FUN_80286128();
  return;
}

