// Function: FUN_801b321c
// Entry: 801b321c
// Size: 1120 bytes

/* WARNING: Removing unreachable block (ram,0x801b32e0) */

void FUN_801b321c(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  undefined8 uVar8;
  double dVar9;
  double dVar10;
  short *local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar5 = *(int *)(param_9 + 0x26);
  if (param_9[0x23] == 0x1d6) {
    FUN_801b2338(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    if (((*(byte *)((int)param_9 + 0xaf) & 8) != 0) &&
       (uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1a)), uVar1 != 0)) {
      *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    }
    piVar6 = *(int **)(param_9 + 0x5c);
    iVar2 = FUN_8002bac4();
    iVar3 = FUN_80297a08(iVar2);
    if (iVar3 == 0) {
      *piVar6 = iVar2;
    }
    else {
      *piVar6 = 0;
    }
    param_9[3] = param_9[3] & 0xbfff;
    bVar4 = *(byte *)(piVar6 + 0x2b);
    if (bVar4 == 4) {
      FUN_801b27f8();
      uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1a));
      if (uVar1 == 0) {
        if ((*piVar6 != 0) && (uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1e)), uVar1 == 0)) {
          dVar7 = FUN_80021730((float *)(param_9 + 0xc),(float *)(*piVar6 + 0x18));
          uStack_1c = *(short *)(iVar5 + 0x26) * DAT_803dcb78 ^ 0x80000000;
          local_20 = 0x43300000;
          if (dVar7 < (double)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5558) /
                              FLOAT_803e5584)) {
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
        uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1a));
        if (uVar1 == 0) {
          uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1e));
          if (uVar1 == 0) {
            if (*piVar6 == 0) {
              *(undefined *)(piVar6 + 0x2b) = 4;
            }
            else {
              *(byte *)((int)piVar6 + 0xaf) = *(char *)((int)piVar6 + 0xaf) + DAT_803dc070;
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
                *(ushort *)(piVar6 + 0x29) = *(short *)(piVar6 + 0x29) - (ushort)DAT_803dc070;
              }
              if (0 < *(short *)((int)piVar6 + 0xa6)) {
                *(ushort *)((int)piVar6 + 0xa6) =
                     *(short *)((int)piVar6 + 0xa6) - (ushort)DAT_803dc070;
              }
              dVar7 = FUN_80021730((float *)(param_9 + 0xc),(float *)(*piVar6 + 0x18));
              piVar6[4] = (int)(float)dVar7;
              dVar7 = (double)(float)piVar6[2];
              dVar9 = (double)(float)piVar6[3];
              dVar10 = (double)(float)piVar6[4];
              uVar8 = FUN_801b27f8();
              FUN_801b25a8(uVar8,dVar7,dVar9,dVar10,param_5,param_6,param_7,param_8);
              uStack_1c = *(short *)(iVar5 + 0x26) * DAT_803dcb74 ^ 0x80000000;
              local_20 = 0x43300000;
              if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5558) / FLOAT_803e5584
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
      else if ((bVar4 == 0) && (uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1c)), uVar1 != 0)) {
        *(undefined *)(piVar6 + 0x2b) = 4;
      }
    }
    else if (bVar4 < 6) {
      if (*(char *)(piVar6 + 0x2c) < '\x01') {
        if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
          *(undefined *)((int)piVar6 + 0xae) = 0;
          *(undefined *)((int)piVar6 + 0xb1) = 0;
          local_28[0] = param_9;
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x51,1,0,4,local_28,0x32,0xff);
          FUN_80014b68(0,0x100);
          *(undefined *)(piVar6 + 0x2b) = 3;
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
          *(undefined *)(piVar6 + 0x2c) = 0x3c;
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)(piVar6 + 0x2c) = *(char *)(piVar6 + 0x2c) - DAT_803dc070;
      }
      *(undefined *)((int)piVar6 + 0xad) = 0;
      *(undefined2 *)(piVar6 + 0x29) = 0;
      *(undefined2 *)((int)piVar6 + 0xa6) = 0;
    }
    FLOAT_803dcb5c = FLOAT_803e5588;
    FUN_8002fb40((double)FLOAT_803e5588,(double)FLOAT_803dc074);
  }
  return;
}

