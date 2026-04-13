// Function: FUN_801c34d8
// Entry: 801c34d8
// Size: 1508 bytes

void FUN_801c34d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  float fVar1;
  bool bVar2;
  double dVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar9;
  int *piVar8;
  ushort *puVar10;
  int iVar11;
  ushort *puVar12;
  undefined8 uVar13;
  
  puVar12 = &DAT_80326bc8;
  iVar11 = *(int *)(param_9 + 0x5c);
  iVar6 = FUN_8002bac4();
  if ((*(int *)(param_9 + 0x7a) != 0) &&
     (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
    uVar13 = FUN_80088f20(7,'\x01');
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar6,0x78,0,in_r7,in_r8,in_r9,in_r10);
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar6,0x79,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6,0x222,
                 0,in_r7,in_r8,in_r9,in_r10);
  }
  FUN_801c2ec8(param_9);
  if (DAT_803dcbc8 != '\0') {
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(param_9 + 10);
    FUN_80297184(iVar6,0x14);
    FUN_800201ac(0x1d7,1);
    DAT_803dcbc8 = '\0';
  }
  FUN_801d8650(iVar11 + 0xc,1,-1,-1,0xcbb,(int *)0x8);
  FUN_801d84c4(iVar11 + 0xc,4,-1,-1,0xcbb,(int *)0xc4);
  fVar4 = FLOAT_803e5b24;
  dVar3 = DOUBLE_803e5b18;
  uVar5 = (int)*(short *)(iVar11 + 0x12) ^ 0x80000000;
  if ((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e5b18) <= FLOAT_803e5b24) {
    switch(*(undefined *)(iVar11 + 0x1a)) {
    case 0:
      fVar1 = *(float *)(iVar11 + 8) - FLOAT_803dc074;
      *(float *)(iVar11 + 8) = fVar1;
      if (fVar1 <= fVar4) {
        FUN_8000bb38((uint)param_9,0x343);
        uVar5 = FUN_80022264(500,1000);
        *(float *)(iVar11 + 8) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e5b18);
      }
      if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
        FUN_800201ac(0x589,0);
        *(undefined *)(iVar11 + 0x1a) = 5;
        FUN_8000a538((int *)0xd8,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        FUN_800201ac(0x129,0);
      }
      break;
    case 1:
      if (*(char *)(iVar11 + 0x1c) < '\0') {
        *(undefined *)(iVar11 + 0x1a) = 2;
        FUN_800201ac(0xb76,1);
        FUN_800146e8(0x19,0xd2);
        FUN_800146c8();
      }
      break;
    case 2:
      if ((*(byte *)(iVar11 + 0x1b) < 10) &&
         (*(float *)(iVar11 + 4) = *(float *)(iVar11 + 4) - FLOAT_803dc074,
         *(float *)(iVar11 + 4) <= fVar4)) {
        FUN_800201ac((uint)(ushort)(&DAT_80326bc8)[*(byte *)(iVar11 + 0x1b)],1);
        *(float *)(iVar11 + 4) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (&DAT_80326bdc + (uint)*(byte *)(iVar11 + 0x1b) * 2)) -
                    DOUBLE_803e5b28);
        *(char *)(iVar11 + 0x1b) = *(char *)(iVar11 + 0x1b) + '\x01';
      }
      bVar2 = false;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        uVar5 = FUN_80020078((uint)(ushort)(&DAT_80326bf0)[sVar9]);
        if (uVar5 == 0) {
          bVar2 = true;
          sVar9 = 10;
        }
      }
      if (bVar2) {
        bVar7 = FUN_8001469c();
        if (bVar7 != 0) {
          *(undefined *)(iVar11 + 0x1a) = 7;
          *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf;
          *(undefined2 *)(iVar11 + 0x12) = 0x78;
          piVar8 = &DAT_80326c04;
          for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
            if ((*piVar8 != -1) && (iVar6 = FUN_8002e1ac(*piVar8), iVar6 != 0)) {
              FUN_8014ca38(iVar6);
            }
            piVar8 = piVar8 + 1;
          }
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 7;
        *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0xbf | 0x40;
        FUN_800146a8();
      }
      break;
    case 3:
      uVar5 = FUN_80296cb4(iVar6,1);
      if ((uVar5 == 0) && (uVar5 = FUN_80020078(0xbfd), uVar5 == 0)) {
        if ((*(byte *)(iVar11 + 0x1c) >> 6 & 1) == 0) {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_800201ac(0xb70,1);
        }
        else {
          *(undefined *)(iVar11 + 0x1a) = 4;
          FUN_80009a94(3);
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
        }
      }
      else {
        *(undefined *)(iVar11 + 0x1a) = 4;
      }
      FUN_800201ac(0x129,1);
      FUN_800201ac(0xb76,0);
      break;
    case 4:
      *(undefined *)(iVar11 + 0x1a) = 0;
      *(byte *)(iVar11 + 0x1c) = *(byte *)(iVar11 + 0x1c) & 0x7f;
      *(undefined *)(iVar11 + 0x1b) = 0;
      *(float *)(iVar11 + 4) = fVar4;
      FUN_800201ac(0x129,1);
      FUN_800201ac(0xb70,0);
      FUN_800201ac(0xb71,0);
      FUN_800201ac(0xb76,0);
      FUN_800201ac(0x589,1);
      puVar10 = &DAT_80326bf0;
      for (sVar9 = 0; sVar9 < 10; sVar9 = sVar9 + 1) {
        FUN_800201ac((uint)*puVar10,0);
        FUN_800201ac((uint)*puVar12,0);
        puVar10 = puVar10 + 1;
        puVar12 = puVar12 + 1;
      }
      param_9[3] = param_9[3] & 0xbfff;
      break;
    case 5:
      *(undefined2 *)(iVar11 + 0x12) = 0x1f;
      (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,1);
      *(undefined *)(iVar11 + 0x1a) = 1;
      param_9[3] = param_9[3] | 0x4000;
      break;
    case 6:
      *(undefined *)(iVar11 + 0x1a) = 3;
      break;
    case 7:
      *(undefined *)(iVar11 + 0x1a) = 6;
      *(undefined2 *)(iVar11 + 0x12) = 0x23;
      (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
    }
  }
  else {
    *(short *)(iVar11 + 0x12) =
         (short)(int)((float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e5b18) - FLOAT_803dc074
                     );
    if ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x12) ^ 0x80000000) - dVar3) <=
        fVar4) {
      *(undefined2 *)(iVar11 + 0x12) = 0;
    }
  }
  return;
}

