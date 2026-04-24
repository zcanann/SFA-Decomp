// Function: FUN_801cd258
// Entry: 801cd258
// Size: 1056 bytes

void FUN_801cd258(int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined4 local_38;
  int local_34;
  int local_30;
  undefined4 local_2c;
  undefined auStack40 [16];
  float local_18;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  local_38 = DAT_802c23d8;
  local_34 = DAT_802c23dc;
  local_30 = DAT_802c23e0;
  local_2c = DAT_802c23e4;
  FUN_8000bb18(param_1,0x72);
  FUN_8005a194(param_1);
  if (0 < *(short *)(piVar3 + 2)) {
    *(ushort *)(piVar3 + 2) = *(short *)(piVar3 + 2) - (ushort)DAT_803db410;
  }
  if (*(char *)((int)piVar3 + 0xb) == '\x01') {
    local_18 = FLOAT_803e51e0;
    *(undefined *)((int)piVar3 + 0xe) = *(undefined *)(piVar3 + 3);
    iVar1 = FUN_8003687c(param_1,0,0,0);
    if ((iVar1 != 0) || ((*(short *)(piVar3 + 2) != 0 && (*(short *)(piVar3 + 2) < 0x15)))) {
      *(char *)(piVar3 + 3) = '\x01' - *(char *)(piVar3 + 3);
      if (*(char *)(piVar3 + 3) != '\0') {
        *(undefined2 *)((int)piVar3 + 6) = 1000;
      }
      if (*(short *)(piVar3 + 2) != 0) {
        *(undefined2 *)(piVar3 + 2) = 0;
        DAT_803ddbe8 = '\x03';
        *(undefined2 *)((int)piVar3 + 6) = 300;
        if (*(char *)((int)piVar3 + 0xf) == '\x02') {
          FUN_800200e8(0x1d1,1);
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
        FUN_8000b7bc(param_1,0x40);
        (**(code **)(*DAT_803dca7c + 0x18))(param_1);
        (**(code **)(*DAT_803dca78 + 0x14))(param_1);
        if ((*piVar3 != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
          FUN_800200e8(*piVar3,0);
        }
        if ((DAT_803ddbe8 == '\x01') && (*(char *)((int)piVar3 + 0xf) == '\0')) {
          DAT_803ddbe8 = '\0';
        }
        if ((DAT_803ddbe8 == '\x02') && (*(char *)((int)piVar3 + 0xf) == '\x01')) {
          DAT_803ddbe8 = '\0';
        }
        if (((DAT_803ddbe8 == '\x03') && (*(char *)((int)piVar3 + 0xf) == '\x02')) &&
           (iVar1 = FUN_8001ffb4(0x1d5), iVar1 == 0)) {
          FUN_800200e8(0x1d1,0);
          DAT_803ddbe8 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80013ec8(0x69,1);
        local_30 = (uint)*(byte *)((int)piVar3 + 0xf) * 2;
        local_34 = local_30 + 0x19d;
        local_30 = local_30 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack40,0x10004,0xffffffff,&local_38);
        FUN_80013e2c(piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 100);
        if ((*piVar3 != -1) && (iVar1 = FUN_8001ffb4(), iVar1 == 0)) {
          FUN_800200e8(*piVar3,1);
        }
        if (((DAT_803ddbe8 == '\0') && (*(char *)((int)piVar3 + 0xf) == '\0')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          DAT_803ddbe8 = '\x01';
        }
        if (((DAT_803ddbe8 == '\x01') && (*(char *)((int)piVar3 + 0xf) == '\x01')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          DAT_803ddbe8 = '\x02';
        }
        if (((DAT_803ddbe8 == '\x02') && (*(char *)((int)piVar3 + 0xf) == '\x02')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          FUN_800200e8(0x1d1,1);
          DAT_803ddbe8 = '\x03';
        }
        *(undefined *)((int)piVar3 + 0xd) = 1;
        *(undefined2 *)(piVar3 + 1) = 1;
      }
    }
  }
  return;
}

