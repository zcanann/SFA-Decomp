// Function: FUN_80058ea8
// Entry: 80058ea8
// Size: 1084 bytes

void FUN_80058ea8(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  short *psVar5;
  int iVar6;
  undefined2 *puVar7;
  int iVar8;
  int local_28 [10];
  
  FUN_802860d4();
  local_28[0] = 0;
  iVar2 = FUN_80048f10(0x15);
  FUN_8001f768(local_28,0x15);
  DAT_80382238 = 0xffffffff;
  DAT_8038223c = FUN_80023cc8(0x500,5,0);
  DAT_80382240 = FUN_80023cc8(0x200,5,0);
  DAT_80382244 = FUN_80023cc8(0x80,5,0);
  DAT_80382248 = FUN_80023cc8(0x2000,5,0);
  FUN_800033a8(DAT_80382248,0,0x2000);
  iVar4 = 0;
  iVar3 = 0;
  iVar6 = 0;
  iVar8 = 0x10;
  do {
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3);
    *(undefined *)(DAT_80382244 + iVar4) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    *(undefined2 *)(DAT_80382240 + iVar6) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar6 + 2) = 0xffff;
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3 + 10);
    *(undefined *)(DAT_80382244 + iVar4 + 1) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    iVar1 = (iVar4 + 1) * 4;
    *(undefined2 *)(DAT_80382240 + iVar1) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar1 + 2) = 0xffff;
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3 + 0x14);
    *(undefined *)(DAT_80382244 + iVar4 + 2) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    iVar1 = (iVar4 + 2) * 4;
    *(undefined2 *)(DAT_80382240 + iVar1) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar1 + 2) = 0xffff;
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3 + 0x1e);
    *(undefined *)(DAT_80382244 + iVar4 + 3) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    iVar1 = (iVar4 + 3) * 4;
    *(undefined2 *)(DAT_80382240 + iVar1) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar1 + 2) = 0xffff;
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3 + 0x28);
    *(undefined *)(DAT_80382244 + iVar4 + 4) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    iVar1 = (iVar4 + 4) * 4;
    *(undefined2 *)(DAT_80382240 + iVar1) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar1 + 2) = 0xffff;
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3 + 0x32);
    *(undefined *)(DAT_80382244 + iVar4 + 5) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    iVar1 = (iVar4 + 5) * 4;
    *(undefined2 *)(DAT_80382240 + iVar1) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar1 + 2) = 0xffff;
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3 + 0x3c);
    *(undefined *)(DAT_80382244 + iVar4 + 6) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    iVar1 = (iVar4 + 6) * 4;
    *(undefined2 *)(DAT_80382240 + iVar1) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar1 + 2) = 0xffff;
    puVar7 = (undefined2 *)(DAT_8038223c + iVar3 + 0x46);
    *(undefined *)(DAT_80382244 + iVar4 + 7) = 0x80;
    *puVar7 = 0x8000;
    puVar7[1] = 0x8000;
    puVar7[2] = 0x8000;
    puVar7[3] = 0x8000;
    *(undefined *)(puVar7 + 4) = 0x80;
    *(undefined *)((int)puVar7 + 9) = 0x80;
    iVar1 = (iVar4 + 7) * 4;
    *(undefined2 *)(DAT_80382240 + iVar1) = 0xffff;
    *(undefined2 *)(DAT_80382240 + iVar1 + 2) = 0xffff;
    iVar3 = iVar3 + 0x50;
    iVar6 = iVar6 + 0x20;
    iVar4 = iVar4 + 8;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  iVar4 = 0;
  iVar2 = iVar2 / 0xc + (iVar2 >> 0x1f);
  for (iVar3 = 0; iVar3 < iVar2 - (iVar2 >> 0x1f); iVar3 = iVar3 + 1) {
    iVar6 = (int)*(short *)(local_28[0] + iVar4 + 6);
    if (iVar6 < 0) break;
    *(char *)(DAT_80382244 + iVar6) = (char)*(undefined2 *)(local_28[0] + iVar4 + 4);
    psVar5 = (short *)(local_28[0] + iVar4);
    FUN_80058d3c(DAT_8038223c + psVar5[3] * 10,DAT_80382248 + psVar5[3] * 0x40,(int)*psVar5,
                 (int)psVar5[1]);
    *(undefined2 *)(DAT_80382240 + *(short *)(local_28[0] + iVar4 + 6) * 4) =
         *(undefined2 *)(local_28[0] + iVar4 + 8);
    *(undefined2 *)(DAT_80382240 + *(short *)(local_28[0] + iVar4 + 6) * 4 + 2) =
         *(undefined2 *)(local_28[0] + iVar4 + 10);
    iVar4 = iVar4 + 0xc;
  }
  DAT_803dcea4 = 0;
  DAT_803dceb6 = 0;
  DAT_803dceb4 = 0;
  FUN_80023800(local_28[0]);
  FUN_80286120();
  return;
}

