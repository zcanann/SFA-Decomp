// Function: FUN_80142ef4
// Entry: 80142ef4
// Size: 448 bytes

void FUN_80142ef4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  bool bVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double extraout_f1;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  if (*(short *)(uVar1 + 0xa0) == 0x1a) {
    dVar9 = (double)*(float *)(uVar1 + 0x98);
    if ((dVar9 <= (double)FLOAT_803e313c) || ((*(uint *)(iVar6 + 0x54) & 0x800) != 0)) {
      if ((*(uint *)(iVar6 + 0x54) & 0x8000000) != 0) {
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffff7ff;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x1000;
        iVar8 = 0;
        iVar7 = iVar6;
        do {
          FUN_801784f8(*(int *)(iVar7 + 0x700));
          iVar7 = iVar7 + 4;
          iVar8 = iVar8 + 1;
        } while (iVar8 < 7);
        FUN_8000dbb0();
        iVar7 = *(int *)(uVar1 + 0xb8);
        if (((*(byte *)(iVar7 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(uVar1 + 0xa0) || (*(short *)(uVar1 + 0xa0) < 0x29)) &&
            (bVar5 = FUN_8000b598(uVar1,0x10), !bVar5)))) {
          FUN_800394f0(uVar1,iVar7 + 0x3a8,0x29d,0,0xffffffff,0);
        }
        *(undefined *)(iVar6 + 10) = 10;
      }
    }
    else {
      uVar2 = FUN_8002e144();
      if ((uVar2 & 0xff) != 0) {
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x800;
        iVar7 = 0;
        do {
          puVar3 = FUN_8002becc(0x24,0x4f0);
          *(undefined *)(puVar3 + 2) = 2;
          *(undefined *)((int)puVar3 + 5) = 1;
          puVar3[0xd] = (short)iVar7;
          uVar4 = FUN_8002e088(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                               5,*(undefined *)(uVar1 + 0xac),0xffffffff,*(uint **)(uVar1 + 0x30),
                               in_r8,in_r9,in_r10);
          *(undefined4 *)(iVar6 + 0x700) = uVar4;
          iVar6 = iVar6 + 4;
          iVar7 = iVar7 + 1;
          dVar9 = extraout_f1;
        } while (iVar7 < 7);
        FUN_8000bb38(uVar1,0x3db);
        FUN_8000dcdc(uVar1,0x3dc);
      }
    }
  }
  else {
    FUN_8013a778((double)FLOAT_803e3074,uVar1,0x1a,0);
  }
  FUN_8028688c();
  return;
}

