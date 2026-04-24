// Function: FUN_80239c18
// Entry: 80239c18
// Size: 600 bytes

void FUN_80239c18(void)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  uint *puVar7;
  int iVar8;
  int local_28 [2];
  longlong local_20;
  
  iVar2 = FUN_80286840();
  puVar7 = *(uint **)(iVar2 + 0xb8);
  bVar1 = *(byte *)((int)puVar7 + 0x1b) >> 4;
  if (bVar1 == 5) {
    piVar3 = FUN_80037048(0x48,local_28);
    iVar6 = 0;
    piVar5 = piVar3;
    iVar8 = local_28[0];
    if (0 < local_28[0]) {
      do {
        if (*(char *)(*(int *)(*piVar5 + 0x4c) + 0x1b) == *(char *)((int)puVar7 + 0x1a)) break;
        piVar5 = piVar5 + 1;
        iVar6 = iVar6 + 1;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
    if (iVar6 == local_28[0]) {
      *(byte *)((int)puVar7 + 0x1b) = *(byte *)((int)puVar7 + 0x1b) & 0xf | 0xa0;
    }
    else {
      uVar4 = FUN_8008fdac((double)(float)puVar7[2],(double)(float)puVar7[3],iVar2 + 0xc,
                           piVar3[iVar6] + 0xc,(ushort)*(byte *)(puVar7 + 6),
                           *(undefined *)((int)puVar7 + 0x19),0);
      *puVar7 = uVar4;
      *(byte *)((int)puVar7 + 0x1b) = *(byte *)((int)puVar7 + 0x1b) & 0xf | 0x60;
      puVar7[1] = (uint)FLOAT_803e80e8;
      if ((*(byte *)((int)puVar7 + 0x1b) & 1) != 0) {
        FUN_800972fc(iVar2,1,7,0x1e,0);
      }
      iVar8 = *(int *)(piVar3[iVar6] + 0xb8);
      if ((*(byte *)(iVar8 + 0x1b) & 1) != 0) {
        FUN_800972fc(piVar3[iVar6],1,7,0x1e,0);
      }
      if ((*(byte *)((int)puVar7 + 0x1b) & 2) != 0) {
        FUN_80097568((double)(float)puVar7[5],(double)FLOAT_803e80ec,iVar2,5,1,1,100,0,0);
      }
      if ((*(byte *)(iVar8 + 0x1b) & 2) != 0) {
        FUN_80097568((double)*(float *)(iVar8 + 0x14),(double)FLOAT_803e80ec,piVar3[iVar6],5,1,1,100
                     ,0,0);
      }
    }
  }
  else if ((bVar1 == 6) && ((float *)*puVar7 != (float *)0x0)) {
    FUN_8008fb90((float *)*puVar7);
    puVar7[1] = (uint)((float)puVar7[1] + FLOAT_803dc074);
    local_20 = (longlong)(int)(FLOAT_803e80f0 + (float)puVar7[1]);
    *(short *)(*puVar7 + 0x20) = (short)(int)(FLOAT_803e80f0 + (float)puVar7[1]);
    uVar4 = *puVar7;
    if (*(ushort *)(uVar4 + 0x22) <= *(ushort *)(uVar4 + 0x20)) {
      FUN_800238c4(uVar4);
      *puVar7 = 0;
      *(byte *)((int)puVar7 + 0x1b) = *(byte *)((int)puVar7 + 0x1b) & 0xf;
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
    }
  }
  FUN_8028688c();
  return;
}

