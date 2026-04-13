// Function: FUN_80059024
// Entry: 80059024
// Size: 1084 bytes

void FUN_80059024(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  uint local_28 [10];
  
  uVar10 = FUN_80286838();
  local_28[0] = 0;
  iVar1 = FUN_8004908c(0x15);
  uVar10 = FUN_8001f82c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_28,0x15
                        ,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_80382e98 = 0xffffffff;
  DAT_80382e9c = FUN_80023d8c(0x500,5);
  DAT_80382ea0 = FUN_80023d8c(0x200,5);
  DAT_80382ea4 = FUN_80023d8c(0x80,5);
  DAT_80382ea8 = FUN_80023d8c(0x2000,5);
  FUN_800033a8(DAT_80382ea8,0,0x2000);
  iVar3 = 0;
  iVar2 = 0;
  iVar5 = 0;
  iVar9 = 0x10;
  do {
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2);
    *(undefined *)(DAT_80382ea4 + iVar3) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    *(undefined2 *)(DAT_80382ea0 + iVar5) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar5 + 2) = 0xffff;
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2 + 10);
    *(undefined *)(DAT_80382ea4 + iVar3 + 1) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    iVar8 = (iVar3 + 1) * 4;
    *(undefined2 *)(DAT_80382ea0 + iVar8) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar8 + 2) = 0xffff;
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2 + 0x14);
    *(undefined *)(DAT_80382ea4 + iVar3 + 2) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    iVar8 = (iVar3 + 2) * 4;
    *(undefined2 *)(DAT_80382ea0 + iVar8) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar8 + 2) = 0xffff;
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2 + 0x1e);
    *(undefined *)(DAT_80382ea4 + iVar3 + 3) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    iVar8 = (iVar3 + 3) * 4;
    *(undefined2 *)(DAT_80382ea0 + iVar8) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar8 + 2) = 0xffff;
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2 + 0x28);
    *(undefined *)(DAT_80382ea4 + iVar3 + 4) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    iVar8 = (iVar3 + 4) * 4;
    *(undefined2 *)(DAT_80382ea0 + iVar8) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar8 + 2) = 0xffff;
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2 + 0x32);
    *(undefined *)(DAT_80382ea4 + iVar3 + 5) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    iVar8 = (iVar3 + 5) * 4;
    *(undefined2 *)(DAT_80382ea0 + iVar8) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar8 + 2) = 0xffff;
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2 + 0x3c);
    *(undefined *)(DAT_80382ea4 + iVar3 + 6) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    iVar8 = (iVar3 + 6) * 4;
    *(undefined2 *)(DAT_80382ea0 + iVar8) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar8 + 2) = 0xffff;
    iVar8 = DAT_80382ea4;
    puVar6 = (undefined2 *)(DAT_80382e9c + iVar2 + 0x46);
    iVar7 = iVar3 + 7;
    *(undefined *)(DAT_80382ea4 + iVar7) = 0x80;
    *puVar6 = 0x8000;
    puVar6[1] = 0x8000;
    puVar6[2] = 0x8000;
    puVar6[3] = 0x8000;
    *(undefined *)(puVar6 + 4) = 0x80;
    *(undefined *)((int)puVar6 + 9) = 0x80;
    *(undefined2 *)(DAT_80382ea0 + iVar7 * 4) = 0xffff;
    *(undefined2 *)(DAT_80382ea0 + iVar7 * 4 + 2) = 0xffff;
    iVar2 = iVar2 + 0x50;
    iVar5 = iVar5 + 0x20;
    iVar3 = iVar3 + 8;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  iVar3 = 0;
  iVar1 = iVar1 / 0xc + (iVar1 >> 0x1f);
  for (iVar2 = 0; iVar2 < iVar1 - (iVar1 >> 0x1f); iVar2 = iVar2 + 1) {
    iVar5 = (int)*(short *)(local_28[0] + iVar3 + 6);
    if (iVar5 < 0) break;
    *(char *)(DAT_80382ea4 + iVar5) = (char)*(undefined2 *)(local_28[0] + iVar3 + 4);
    psVar4 = (short *)(local_28[0] + iVar3);
    iVar5 = (int)psVar4[3];
    uVar10 = FUN_80058eb8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                          DAT_80382e9c + iVar5 * 10,DAT_80382ea8 + iVar5 * 0x40,*psVar4,psVar4[1],
                          iVar5,iVar7,iVar8,puVar6);
    *(undefined2 *)(DAT_80382ea0 + *(short *)(local_28[0] + iVar3 + 6) * 4) =
         *(undefined2 *)(local_28[0] + iVar3 + 8);
    *(undefined2 *)(DAT_80382ea0 + *(short *)(local_28[0] + iVar3 + 6) * 4 + 2) =
         *(undefined2 *)(local_28[0] + iVar3 + 10);
    iVar3 = iVar3 + 0xc;
  }
  DAT_803ddb24 = 0;
  DAT_803ddb36 = 0;
  DAT_803ddb34 = 0;
  FUN_800238c4(local_28[0]);
  FUN_80286884();
  return;
}

