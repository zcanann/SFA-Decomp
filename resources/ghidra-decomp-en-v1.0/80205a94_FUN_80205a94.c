// Function: FUN_80205a94
// Entry: 80205a94
// Size: 888 bytes

void FUN_80205a94(int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack56 [16];
  float local_28;
  longlong local_20;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  local_48 = DAT_802c2510;
  local_44 = DAT_802c2514;
  local_40 = DAT_802c2518;
  local_3c = DAT_802c251c;
  FUN_8000bb18(param_1,0x72);
  FUN_8005a194(param_1);
  if (*(char *)((int)piVar3 + 9) == '\x01') {
    local_28 = FLOAT_803e63e0;
    *(undefined *)(piVar3 + 3) = *(undefined *)((int)piVar3 + 10);
    iVar1 = FUN_8003687c(param_1,0,0,0);
    if ((iVar1 != 0) &&
       (*(char *)((int)piVar3 + 10) = '\x01' - *(char *)((int)piVar3 + 10),
       *(char *)((int)piVar3 + 10) != '\0')) {
      *(undefined2 *)((int)piVar3 + 6) = 2000;
    }
    if ((*(char *)((int)piVar3 + 10) != '\0') && (*(short *)((int)piVar3 + 6) != 0)) {
      local_20 = (longlong)(int)FLOAT_803db414;
      *(short *)((int)piVar3 + 6) = *(short *)((int)piVar3 + 6) - (short)(int)FLOAT_803db414;
      if (*(short *)((int)piVar3 + 6) < 1) {
        *(undefined2 *)((int)piVar3 + 6) = 0;
        *(undefined *)((int)piVar3 + 10) = 0;
      }
    }
    if (((*(char *)((int)piVar3 + 10) != '\0') && (*(short *)(piVar3 + 1) < 1)) &&
       (*(char *)((int)piVar3 + 0xb) != '\0')) {
      *(undefined *)((int)piVar3 + 0xb) = 0;
      FUN_8000bb18(param_1,0x80);
    }
    if (*(char *)((int)piVar3 + 10) != *(char *)(piVar3 + 3)) {
      if (*(char *)((int)piVar3 + 10) == '\0') {
        FUN_8000b7bc(param_1,0x40);
        (**(code **)(*DAT_803dca7c + 0x18))(param_1);
        (**(code **)(*DAT_803dca78 + 0x14))(param_1);
        if ((*piVar3 != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
          FUN_800200e8(*piVar3,0);
        }
        if ((DAT_803ddce8 == '\x01') && (*(char *)((int)piVar3 + 0xd) == '\0')) {
          DAT_803ddce8 = '\0';
        }
        if (((DAT_803ddce8 == '\x02') && (*(char *)((int)piVar3 + 0xd) == '\x01')) &&
           (iVar1 = FUN_8001ffb4(0x5e2), iVar1 == 0)) {
          FUN_800200e8(0x5e2,0);
          DAT_803ddce8 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80013ec8(0x69,1);
        local_40 = (uint)*(byte *)((int)piVar3 + 0xd) * 2;
        local_44 = local_40 + 0x19d;
        local_40 = local_40 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack56,0x10004,0xffffffff,&local_48);
        FUN_80013e2c(piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 100);
        if ((*piVar3 != -1) && (iVar1 = FUN_8001ffb4(), iVar1 == 0)) {
          FUN_800200e8(*piVar3,1);
        }
        if (((DAT_803ddce8 == '\0') && (*(char *)((int)piVar3 + 0xd) == '\0')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          DAT_803ddce8 = '\x01';
        }
        if (((DAT_803ddce8 == '\x01') && (*(char *)((int)piVar3 + 0xd) == '\x01')) &&
           (iVar1 = FUN_8001ffb4(*piVar3), iVar1 != 0)) {
          FUN_800200e8(0x5e2,1);
          DAT_803ddce8 = '\x02';
        }
        *(undefined *)((int)piVar3 + 0xb) = 1;
        *(undefined2 *)(piVar3 + 1) = 1;
      }
    }
  }
  return;
}

