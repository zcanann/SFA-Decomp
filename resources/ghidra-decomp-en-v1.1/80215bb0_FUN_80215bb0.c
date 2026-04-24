// Function: FUN_80215bb0
// Entry: 80215bb0
// Size: 976 bytes

void FUN_80215bb0(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined2 uVar1;
  int iVar2;
  undefined2 *puVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  undefined4 uVar8;
  int iVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  int iVar12;
  undefined4 *puVar13;
  undefined4 *puVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar17;
  
  uVar17 = FUN_80286834();
  puVar3 = (undefined2 *)((ulonglong)uVar17 >> 0x20);
  DAT_803de9d8 = *(int *)(puVar3 + 0x5c);
  uVar8 = 0x10;
  if (param_3 != 0) {
    uVar8 = 0x11;
  }
  iVar9 = *DAT_803dd738;
  (**(code **)(iVar9 + 0x58))((double)FLOAT_803e74e4,puVar3,(int)uVar17,DAT_803de9d8,9,0xc,0x100);
  *(code **)(puVar3 + 0x5e) = FUN_802150c0;
  iVar2 = DAT_803de9d8;
  (**(code **)(*DAT_803dd70c + 0x14))(puVar3,DAT_803de9d8,0);
  *(undefined2 *)(iVar2 + 0x270) = 2;
  *(undefined4 *)(iVar2 + 0x2d0) = 0;
  *(undefined *)(iVar2 + 0x25f) = 0;
  *(undefined *)(iVar2 + 0x349) = 0;
  *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 0x88;
  FUN_80036018((int)puVar3);
  iVar4 = *(int *)(puVar3 + 0x32);
  if (iVar4 != 0) {
    *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x810;
  }
  DAT_803de9d4 = *(undefined4 **)(DAT_803de9d8 + 0x40c);
  uVar5 = FUN_80013a08(4,4);
  *DAT_803de9d4 = uVar5;
  uVar1 = (undefined2)((int)*(char *)((int)uVar17 + 0x2a) << 8);
  *puVar3 = uVar1;
  *(undefined2 *)(DAT_803de9d4 + 0x3e) = uVar1;
  iVar4 = 0;
  puVar13 = &DAT_8032b1b4;
  iVar12 = 0;
  puVar11 = &DAT_8032b1a4;
  puVar10 = &DAT_8032b1d4;
  puVar14 = &DAT_8032b1c4;
  do {
    iVar6 = (**(code **)(*DAT_803dd71c + 0x1c))(*puVar13);
    if (iVar6 != 0) {
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x10) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x20) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x30) = *(undefined4 *)(iVar6 + 0x10);
      iVar6 = (**(code **)(*DAT_803dd71c + 0x1c))(*puVar11);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x40) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x50) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x60) = *(undefined4 *)(iVar6 + 0x10);
      iVar6 = (**(code **)(*DAT_803dd71c + 0x1c))(*puVar10);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x70) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x80) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0x90) = *(undefined4 *)(iVar6 + 0x10);
      iVar6 = (**(code **)(*DAT_803dd71c + 0x1c))(*puVar14);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0xa0) = *(undefined4 *)(iVar6 + 8);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0xb0) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined4 *)((int)DAT_803de9d4 + iVar12 + 0xc0) = *(undefined4 *)(iVar6 + 0x10);
    }
    puVar13 = puVar13 + 1;
    iVar12 = iVar12 + 4;
    puVar11 = puVar11 + 1;
    puVar10 = puVar10 + 1;
    puVar14 = puVar14 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 4);
  DAT_803de9d4[0x34] = DAT_803de9d4 + 4;
  DAT_803de9d4[0x35] = DAT_803de9d4 + 8;
  DAT_803de9d4[0x36] = DAT_803de9d4 + 0xc;
  DAT_803de9d4[0x37] = DAT_803de9d4 + 0x10;
  DAT_803de9d4[0x38] = DAT_803de9d4 + 0x14;
  DAT_803de9d4[0x39] = DAT_803de9d4 + 0x18;
  *(undefined *)((int)DAT_803de9d4 + 0x102) = 4;
  *(undefined *)(iVar2 + 0x354) = 3;
  DAT_803de9c8 = FUN_80013ee8(0x5a);
  *(undefined4 *)(puVar3 + 0x7c) = 0;
  DAT_803de9d0 = FUN_80059460();
  piVar7 = FUN_8001f58c(0,'\x01');
  DAT_803de9d4[0x5e] = piVar7;
  if (DAT_803de9d4[0x5e] != 0) {
    FUN_8001dbf0(DAT_803de9d4[0x5e],2);
    dVar16 = (double)*(float *)(puVar3 + 10);
    FUN_8001de4c((double)*(float *)(puVar3 + 6),(double)*(float *)(puVar3 + 8),dVar16,
                 (int *)DAT_803de9d4[0x5e]);
    FUN_8001dbb4(DAT_803de9d4[0x5e],0xff,0,0,0);
    dVar15 = (double)FLOAT_803e7488;
    FUN_8001dcfc((double)FLOAT_803e74e8,dVar15,DAT_803de9d4[0x5e]);
    FUN_8001d7f4((double)FLOAT_803e7488,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,
                 DAT_803de9d4[0x5e],0,0xff,0,0,0x50,uVar8,iVar9);
    FUN_8001d7d8((double)FLOAT_803e7454,DAT_803de9d4[0x5e]);
  }
  FUN_8000a3a0(3,2,500);
  FUN_80286880();
  return;
}

