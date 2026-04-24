// Function: FUN_80215538
// Entry: 80215538
// Size: 976 bytes

void FUN_80215538(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined2 uVar1;
  int iVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  int iVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860d0();
  puVar3 = (undefined2 *)((ulonglong)uVar12 >> 0x20);
  DAT_803ddd58 = *(int *)(puVar3 + 0x5c);
  uVar6 = 0x10;
  if (param_3 != 0) {
    uVar6 = 0x11;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))
            ((double)FLOAT_803e684c,puVar3,(int)uVar12,DAT_803ddd58,9,0xc,0x100,uVar6);
  *(code **)(puVar3 + 0x5e) = FUN_80214a48;
  iVar2 = DAT_803ddd58;
  (**(code **)(*DAT_803dca8c + 0x14))(puVar3,DAT_803ddd58,0);
  *(undefined2 *)(iVar2 + 0x270) = 2;
  *(undefined4 *)(iVar2 + 0x2d0) = 0;
  *(undefined *)(iVar2 + 0x25f) = 0;
  *(undefined *)(iVar2 + 0x349) = 0;
  *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 0x88;
  FUN_80035f20(puVar3);
  iVar4 = *(int *)(puVar3 + 0x32);
  if (iVar4 != 0) {
    *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x810;
  }
  DAT_803ddd54 = *(undefined4 **)(DAT_803ddd58 + 0x40c);
  uVar6 = FUN_800139e8(4,4);
  *DAT_803ddd54 = uVar6;
  uVar1 = (undefined2)((int)*(char *)((int)uVar12 + 0x2a) << 8);
  *puVar3 = uVar1;
  *(undefined2 *)(DAT_803ddd54 + 0x3e) = uVar1;
  iVar4 = 0;
  puVar10 = &DAT_8032a55c;
  iVar9 = 0;
  puVar8 = &DAT_8032a54c;
  puVar7 = &DAT_8032a57c;
  puVar11 = &DAT_8032a56c;
  do {
    iVar5 = (**(code **)(*DAT_803dca9c + 0x1c))(*puVar10);
    if (iVar5 != 0) {
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x10) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x20) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x30) = *(undefined4 *)(iVar5 + 0x10);
      iVar5 = (**(code **)(*DAT_803dca9c + 0x1c))(*puVar8);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x40) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x50) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x60) = *(undefined4 *)(iVar5 + 0x10);
      iVar5 = (**(code **)(*DAT_803dca9c + 0x1c))(*puVar7);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x70) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x80) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0x90) = *(undefined4 *)(iVar5 + 0x10);
      iVar5 = (**(code **)(*DAT_803dca9c + 0x1c))(*puVar11);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0xa0) = *(undefined4 *)(iVar5 + 8);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0xb0) = *(undefined4 *)(iVar5 + 0xc);
      *(undefined4 *)((int)DAT_803ddd54 + iVar9 + 0xc0) = *(undefined4 *)(iVar5 + 0x10);
    }
    puVar10 = puVar10 + 1;
    iVar9 = iVar9 + 4;
    puVar8 = puVar8 + 1;
    puVar7 = puVar7 + 1;
    puVar11 = puVar11 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 4);
  DAT_803ddd54[0x34] = DAT_803ddd54 + 4;
  DAT_803ddd54[0x35] = DAT_803ddd54 + 8;
  DAT_803ddd54[0x36] = DAT_803ddd54 + 0xc;
  DAT_803ddd54[0x37] = DAT_803ddd54 + 0x10;
  DAT_803ddd54[0x38] = DAT_803ddd54 + 0x14;
  DAT_803ddd54[0x39] = DAT_803ddd54 + 0x18;
  *(undefined *)((int)DAT_803ddd54 + 0x102) = 4;
  *(undefined *)(iVar2 + 0x354) = 3;
  DAT_803ddd48 = FUN_80013ec8(0x5a,1);
  *(undefined4 *)(puVar3 + 0x7c) = 0;
  DAT_803ddd50 = FUN_800592e4();
  uVar6 = FUN_8001f4c8(0,1);
  DAT_803ddd54[0x5e] = uVar6;
  if (DAT_803ddd54[0x5e] != 0) {
    FUN_8001db2c(DAT_803ddd54[0x5e],2);
    FUN_8001dd88((double)*(float *)(puVar3 + 6),(double)*(float *)(puVar3 + 8),
                 (double)*(float *)(puVar3 + 10),DAT_803ddd54[0x5e]);
    FUN_8001daf0(DAT_803ddd54[0x5e],0xff,0,0,0);
    FUN_8001dc38((double)FLOAT_803e6850,(double)FLOAT_803e67f0,DAT_803ddd54[0x5e]);
    FUN_8001d730((double)FLOAT_803e67f0,DAT_803ddd54[0x5e],0,0xff,0,0,0x50);
    FUN_8001d714((double)FLOAT_803e67bc,DAT_803ddd54[0x5e]);
  }
  FUN_8000a380(3,2,500);
  FUN_8028611c();
  return;
}

