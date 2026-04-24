// Function: FUN_801b2c68
// Entry: 801b2c68
// Size: 1120 bytes

/* WARNING: Removing unreachable block (ram,0x801b2d2c) */

void FUN_801b2c68(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  int local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x46) == 0x1d6) {
    FUN_801b1d84();
  }
  else {
    if (((*(byte *)(param_1 + 0xaf) & 8) != 0) &&
       (iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1a)), iVar2 != 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    }
    piVar6 = *(int **)(param_1 + 0xb8);
    iVar2 = FUN_8002b9ec();
    iVar3 = FUN_802972a8();
    if (iVar3 == 0) {
      *piVar6 = iVar2;
    }
    else {
      *piVar6 = 0;
    }
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    bVar4 = *(byte *)(piVar6 + 0x2b);
    if (bVar4 == 4) {
      FUN_801b2244((double)(float)piVar6[1],(double)(float)piVar6[2],(double)(float)piVar6[3],
                   (double)(float)piVar6[4],param_1);
      iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1a));
      if (iVar2 == 0) {
        if ((*piVar6 != 0) && (iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1e)), iVar2 == 0)) {
          dVar7 = (double)FUN_8002166c(param_1 + 0x18,*piVar6 + 0x18);
          uStack28 = *(short *)(iVar5 + 0x26) * DAT_803dbf10 ^ 0x80000000;
          local_20 = 0x43300000;
          if (dVar7 < (double)((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e48c0) /
                              FLOAT_803e48ec)) {
            *(undefined *)(piVar6 + 0x2b) = 1;
          }
        }
      }
      else {
        *(undefined *)(piVar6 + 0x2b) = 5;
      }
      *(undefined *)((int)piVar6 + 0xad) = 0;
      *(undefined2 *)(piVar6 + 0x29) = 0;
      *(undefined2 *)((int)piVar6 + 0xa6) = 0;
    }
    else if (bVar4 < 4) {
      if (bVar4 == 1) {
        iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1a));
        if (iVar2 == 0) {
          iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1e));
          if (iVar2 == 0) {
            if (*piVar6 == 0) {
              *(undefined *)(piVar6 + 0x2b) = 4;
            }
            else {
              *(byte *)((int)piVar6 + 0xaf) = *(char *)((int)piVar6 + 0xaf) + DAT_803db410;
              if (10 < *(byte *)((int)piVar6 + 0xaf)) {
                *(undefined *)((int)piVar6 + 0xaf) = 0;
                for (bVar4 = 0; bVar4 < 9; bVar4 = bVar4 + 1) {
                  uVar1 = (uint)bVar4;
                  piVar6[uVar1 + 5] = piVar6[uVar1 + 6];
                  piVar6[uVar1 + 0xf] = piVar6[uVar1 + 0x10];
                  piVar6[uVar1 + 0x19] = piVar6[uVar1 + 0x1a];
                  if ((uVar1 == 0) || ((float)piVar6[2] < (float)piVar6[uVar1 + 0xf])) {
                    piVar6[2] = piVar6[uVar1 + 0xf];
                  }
                }
                piVar6[0xe] = *(int *)(*piVar6 + 0xc);
                piVar6[0x18] = *(int *)(*piVar6 + 0x10);
                piVar6[0x22] = *(int *)(*piVar6 + 0x14);
                piVar6[1] = piVar6[5];
                piVar6[3] = piVar6[0x19];
              }
              if (0 < *(short *)(piVar6 + 0x29)) {
                *(ushort *)(piVar6 + 0x29) = *(short *)(piVar6 + 0x29) - (ushort)DAT_803db410;
              }
              if (0 < *(short *)((int)piVar6 + 0xa6)) {
                *(ushort *)((int)piVar6 + 0xa6) =
                     *(short *)((int)piVar6 + 0xa6) - (ushort)DAT_803db410;
              }
              dVar7 = (double)FUN_8002166c(param_1 + 0x18,*piVar6 + 0x18);
              piVar6[4] = (int)(float)dVar7;
              FUN_801b2244((double)(float)piVar6[1],(double)(float)piVar6[2],
                           (double)(float)piVar6[3],(double)(float)piVar6[4],param_1);
              FUN_801b1ff4(param_1,0);
              uStack28 = *(short *)(iVar5 + 0x26) * DAT_803dbf0c ^ 0x80000000;
              local_20 = 0x43300000;
              if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e48c0) / FLOAT_803e48ec
                  < (float)piVar6[4]) {
                *(undefined *)(piVar6 + 0x2b) = 4;
              }
            }
          }
          else {
            *(undefined *)(piVar6 + 0x2b) = 4;
          }
        }
        else {
          *(undefined *)(piVar6 + 0x2b) = 5;
        }
      }
      else if ((bVar4 == 0) && (iVar5 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1c)), iVar5 != 0)) {
        *(undefined *)(piVar6 + 0x2b) = 4;
      }
    }
    else if (bVar4 < 6) {
      if (*(char *)(piVar6 + 0x2c) < '\x01') {
        if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
          *(undefined *)((int)piVar6 + 0xae) = 0;
          *(undefined *)((int)piVar6 + 0xb1) = 0;
          local_28[0] = param_1;
          (**(code **)(*DAT_803dca50 + 0x1c))(0x51,1,0,4,local_28,0x32,0xff);
          FUN_80014b3c(0,0x100);
          *(undefined *)(piVar6 + 0x2b) = 3;
          (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
          *(undefined *)(piVar6 + 0x2c) = 0x3c;
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)(piVar6 + 0x2c) = *(char *)(piVar6 + 0x2c) - DAT_803db410;
      }
      *(undefined *)((int)piVar6 + 0xad) = 0;
      *(undefined2 *)(piVar6 + 0x29) = 0;
      *(undefined2 *)((int)piVar6 + 0xa6) = 0;
    }
    FLOAT_803dbef4 = FLOAT_803e48f0;
    FUN_8002fa48((double)FLOAT_803e48f0,(double)FLOAT_803db414,param_1,0);
  }
  return;
}

