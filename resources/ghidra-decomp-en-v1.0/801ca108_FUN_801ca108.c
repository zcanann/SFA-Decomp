// Function: FUN_801ca108
// Entry: 801ca108
// Size: 1196 bytes

/* WARNING: Removing unreachable block (ram,0x801ca590) */

void FUN_801ca108(int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack56 [16];
  float local_28;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar3 = *(int **)(param_1 + 0xb8);
  local_48 = DAT_802c23c8;
  local_44 = DAT_802c23cc;
  local_40 = DAT_802c23d0;
  local_3c = DAT_802c23d4;
  iVar1 = FUN_8002b9ec();
  dVar5 = (double)FUN_80021704(iVar1 + 0x18,param_1 + 0x18);
  iVar1 = FUN_8000b578(param_1,0x40);
  if (iVar1 == 0) {
    if ((dVar5 < (double)FLOAT_803e5138) && (*(char *)(piVar3 + 3) != '\0')) {
      FUN_8000bb18(param_1,0x72);
    }
  }
  else if (((double)FLOAT_803e5138 <= dVar5) && (*(char *)(piVar3 + 3) != '\0')) {
    FUN_8000b7bc(param_1,0x40);
  }
  FUN_8005a194(param_1);
  if (0 < *(short *)(piVar3 + 2)) {
    *(ushort *)(piVar3 + 2) = *(short *)(piVar3 + 2) - (ushort)DAT_803db410;
  }
  if (*(char *)((int)piVar3 + 0xb) == '\x01') {
    local_28 = FLOAT_803e513c;
    *(undefined *)((int)piVar3 + 0xe) = *(undefined *)(piVar3 + 3);
    iVar1 = FUN_8003687c(param_1,0,0,0);
    if ((iVar1 != 0) || ((*(short *)(piVar3 + 2) != 0 && (*(short *)(piVar3 + 2) < 0x15)))) {
      *(char *)(piVar3 + 3) = '\x01' - *(char *)(piVar3 + 3);
      if (*(char *)(piVar3 + 3) != '\0') {
        *(undefined2 *)((int)piVar3 + 6) = 1000;
      }
      if (*(short *)(piVar3 + 2) != 0) {
        *(undefined2 *)(piVar3 + 2) = 0;
        DAT_803ddbd0 = '\x03';
        *(undefined2 *)((int)piVar3 + 6) = 300;
        if (*(char *)((int)piVar3 + 0xf) == '\x02') {
          FUN_800200e8(0x472,1);
        }
      }
    }
    if (((*(char *)(piVar3 + 3) != '\0') && (*(short *)((int)piVar3 + 6) != 0)) &&
       (*(ushort *)((int)piVar3 + 6) = *(short *)((int)piVar3 + 6) - (ushort)DAT_803db410,
       *(short *)((int)piVar3 + 6) < 1)) {
      *(undefined2 *)((int)piVar3 + 6) = 0;
      *(undefined *)(piVar3 + 3) = 0;
    }
    if (((*(char *)(piVar3 + 3) != '\0') && (*(short *)(piVar3 + 1) < 1)) &&
       (*(char *)((int)piVar3 + 0xd) != '\0')) {
      *(undefined *)((int)piVar3 + 0xd) = 0;
      FUN_8000bb18(param_1,0x80);
    }
    if (*(char *)(piVar3 + 3) != *(char *)((int)piVar3 + 0xe)) {
      if (*(char *)(piVar3 + 3) == '\0') {
        FUN_8000b7bc(param_1,0x7f);
        (**(code **)(*DAT_803dca7c + 0x18))(param_1);
        (**(code **)(*DAT_803dca78 + 0x14))(param_1);
        if ((*piVar3 != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
          FUN_800200e8(*piVar3,0);
        }
        if ((DAT_803ddbd0 == '\x01') && (*(char *)((int)piVar3 + 0xf) == '\0')) {
          DAT_803ddbd0 = '\0';
        }
        if ((DAT_803ddbd0 == '\x02') && (*(char *)((int)piVar3 + 0xf) == '\x01')) {
          DAT_803ddbd0 = '\0';
        }
        if (((DAT_803ddbd0 == '\x03') && (*(char *)((int)piVar3 + 0xf) == '\x02')) &&
           (iVar1 = FUN_8001ffb4(0x474), iVar1 == 0)) {
          FUN_800200e8(0x472,0);
          DAT_803ddbd0 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80013ec8(0x69,1);
        local_40 = (uint)*(byte *)((int)piVar3 + 0xf) * 2;
        local_44 = local_40 + 0x19d;
        local_40 = local_40 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack56,0x10004,0xffffffff,&local_48);
        FUN_80013e2c(piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 200);
        if ((*piVar3 != -1) && (iVar1 = FUN_8001ffb4(), iVar1 == 0)) {
          FUN_800200e8(*piVar3,1);
        }
        if (((DAT_803ddbd0 == '\0') && (*(char *)((int)piVar3 + 0xf) == '\0')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          DAT_803ddbd0 = '\x01';
        }
        if (((DAT_803ddbd0 == '\x01') && (*(char *)((int)piVar3 + 0xf) == '\x01')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          DAT_803ddbd0 = '\x02';
        }
        if (((DAT_803ddbd0 == '\x02') && (*(char *)((int)piVar3 + 0xf) == '\x02')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          FUN_800200e8(0x472,1);
          DAT_803ddbd0 = '\x03';
        }
        *(undefined *)((int)piVar3 + 0xd) = 1;
        *(undefined2 *)(piVar3 + 1) = 1;
      }
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

