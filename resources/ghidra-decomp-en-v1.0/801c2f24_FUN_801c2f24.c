// Function: FUN_801c2f24
// Entry: 801c2f24
// Size: 1508 bytes

void FUN_801c2f24(int param_1)

{
  bool bVar1;
  float fVar2;
  double dVar3;
  float fVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  short sVar9;
  int *piVar8;
  undefined2 *puVar10;
  int iVar11;
  undefined2 *puVar12;
  
  puVar12 = &DAT_80325f88;
  iVar11 = *(int *)(param_1 + 0xb8);
  uVar6 = FUN_8002b9ec();
  if ((*(int *)(param_1 + 0xf4) != 0) &&
     (*(int *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) + -1, *(int *)(param_1 + 0xf4) == 0)) {
    FUN_80088c94(7,1);
    FUN_80008cbc(param_1,uVar6,0x78,0);
    FUN_80008cbc(param_1,uVar6,0x79,0);
    FUN_80008cbc(param_1,uVar6,0x222,0);
  }
  FUN_801c2914(param_1);
  if (DAT_803dbf60 != '\0') {
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(param_1 + 0x14);
    FUN_80296a24(uVar6,0x14);
    FUN_800200e8(0x1d7,1);
    DAT_803dbf60 = '\0';
  }
  FUN_801d8060(iVar11 + 0xc,1,0xffffffff,0xffffffff,0xcbb,8);
  FUN_801d7ed4(iVar11 + 0xc,4,0xffffffff,0xffffffff,0xcbb,0xc4);
  fVar4 = FLOAT_803e4e8c;
  dVar3 = DOUBLE_803e4e80;
  uVar5 = (int)*(short *)(iVar11 + 0x12) ^ 0x80000000;
  if ((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e4e80) <= FLOAT_803e4e8c) {
    switch(*(undefined *)(iVar11 + 0x1a)) {
    case 0:
      fVar2 = *(float *)(iVar11 + 8) - FLOAT_803db414;
      *(float *)(iVar11 + 8) = fVar2;
      if (fVar2 <= fVar4) {
        FUN_8000bb18(param_1,0x343);
        uVar5 = FUN_800221a0(500,1000);
        *(float *)(iVar11 + 8) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e4e80);
      }
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        FUN_800200e8(0x589,0);
        *(undefined *)(iVar11 + 0x1a) = 5;
        FUN_8000a518(0xd8,1);
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        FUN_800200e8(0x129,0);
      }
      break;
    case 1:
      if (*(char *)(iVar11 + 0x1c) < '\0') {
        *(undefined *)(iVar11 + 0x1a) = 2;
        FUN_800200e8(0xb76,1);
        FUN_800146bc(0x19,0xd2);
        FUN_8001469c();
      }
      break;
    case 2:
      if ((*(byte *)(iVar11 + 0x1b) < 10) &&
         (*(float *)(iVar11 + 4) = *(float *)(iVar11 + 4) - FLOAT_803db414,
         *(float *)(iVar11 + 4) <= fVar4)) {
        FUN_800200e8((&DAT_80325f88)[*(byte *)(iVar11 + 0x1b)],1);
        *(float *)(iVar11 + 4) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (&DAT_80325f9c + (uint)*(byte *)(iVar11 + 0x1b) * 2)) -
                    DOUBLE_803e4e90);
        *(char *)(iVar11 + 0x1b) = *(char *)(iVar11 + 0x1b) + '\x01';
      }
      bVar1 = false;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        iVar7 = FUN_8001ffb4((&DAT_80325fb0)[sVar9]);
        if (iVar7 == 0) {
          bVar1 = true;
          sVar9 = 10;
        }
      }
      if (bVar1) {
        iVar7 = FUN_80014670();
        if (iVar7 != 0) {
          *(undefined *)(iVar11 + 0x1a) = 7;
          *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf;
          *(undefined2 *)(iVar11 + 0x12) = 0x78;
          piVar8 = &DAT_80325fc4;
          for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
            if ((*piVar8 != -1) && (iVar11 = FUN_8002e0b4(), iVar11 != 0)) {
              FUN_8014c5c0();
            }
            piVar8 = piVar8 + 1;
          }
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 7;
        *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf | 0x40;
        FUN_8001467c();
      }
      break;
    case 3:
      iVar7 = FUN_80296554(uVar6,1);
      if ((iVar7 == 0) && (iVar7 = FUN_8001ffb4(0xbfd), iVar7 == 0)) {
        if ((*(byte *)(iVar11 + 0x1c) >> 6 & 1) == 0) {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_800200e8(0xb70,1);
        }
        else {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_80009a94(3);
          (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 4;
      }
      FUN_800200e8(0x129,1);
      FUN_800200e8(0xb76,0);
      break;
    case 4:
      *(undefined *)(iVar11 + 0x1a) = 0;
      *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0x7f;
      *(undefined *)(iVar11 + 0x1b) = 0;
      *(float *)(iVar11 + 4) = fVar4;
      FUN_800200e8(0x129,1);
      FUN_800200e8(0xb70,0);
      FUN_800200e8(0xb71,0);
      FUN_800200e8(0xb76,0);
      FUN_800200e8(0x589,1);
      puVar10 = &DAT_80325fb0;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        FUN_800200e8(*puVar10,0);
        FUN_800200e8(*puVar12,0);
        puVar10 = puVar10 + 1;
        puVar12 = puVar12 + 1;
      }
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      break;
    case 5:
      *(undefined2 *)(iVar11 + 0x12) = 0x1f;
      (**(code **)(*DAT_803dca4c + 0xc))(0x1e,1);
      *(undefined *)(iVar11 + 0x1a) = 1;
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      break;
    case 6:
      *(undefined *)(iVar11 + 0x1a) = 3;
      break;
    case 7:
      *(undefined *)(iVar11 + 0x1a) = 6;
      *(undefined2 *)(iVar11 + 0x12) = 0x23;
      (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
    }
  }
  else {
    *(short *)(iVar11 + 0x12) =
         (short)(int)((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e4e80) - FLOAT_803db414
                     );
    if ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x12) ^ 0x80000000) - dVar3) <=
        fVar4) {
      *(undefined2 *)(iVar11 + 0x12) = 0;
    }
  }
  return;
}

