// Function: FUN_801ca6bc
// Entry: 801ca6bc
// Size: 1196 bytes

/* WARNING: Removing unreachable block (ram,0x801cab44) */
/* WARNING: Removing unreachable block (ram,0x801ca6cc) */

void FUN_801ca6bc(uint param_1)

{
  int iVar1;
  bool bVar4;
  int *piVar2;
  uint uVar3;
  uint *puVar5;
  double dVar6;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack_38 [16];
  float local_28;
  
  puVar5 = *(uint **)(param_1 + 0xb8);
  local_48 = DAT_802c2b48;
  local_44 = DAT_802c2b4c;
  local_40 = DAT_802c2b50;
  local_3c = DAT_802c2b54;
  iVar1 = FUN_8002bac4();
  dVar6 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(param_1 + 0x18));
  bVar4 = FUN_8000b598(param_1,0x40);
  if (bVar4) {
    if (((double)FLOAT_803e5dd0 <= dVar6) && (*(char *)(puVar5 + 3) != '\0')) {
      FUN_8000b7dc(param_1,0x40);
    }
  }
  else if ((dVar6 < (double)FLOAT_803e5dd0) && (*(char *)(puVar5 + 3) != '\0')) {
    FUN_8000bb38(param_1,0x72);
  }
  FUN_8005a310(param_1);
  if (0 < *(short *)(puVar5 + 2)) {
    *(ushort *)(puVar5 + 2) = *(short *)(puVar5 + 2) - (ushort)DAT_803dc070;
  }
  if (*(char *)((int)puVar5 + 0xb) == '\x01') {
    local_28 = FLOAT_803e5dd4;
    *(undefined *)((int)puVar5 + 0xe) = *(undefined *)(puVar5 + 3);
    iVar1 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((iVar1 != 0) || ((*(short *)(puVar5 + 2) != 0 && (*(short *)(puVar5 + 2) < 0x15)))) {
      *(char *)(puVar5 + 3) = '\x01' - *(char *)(puVar5 + 3);
      if (*(char *)(puVar5 + 3) != '\0') {
        *(undefined2 *)((int)puVar5 + 6) = 1000;
      }
      if (*(short *)(puVar5 + 2) != 0) {
        *(undefined2 *)(puVar5 + 2) = 0;
        DAT_803de850 = '\x03';
        *(undefined2 *)((int)puVar5 + 6) = 300;
        if (*(char *)((int)puVar5 + 0xf) == '\x02') {
          FUN_800201ac(0x472,1);
        }
      }
    }
    if (((*(char *)(puVar5 + 3) != '\0') && (*(short *)((int)puVar5 + 6) != 0)) &&
       (*(ushort *)((int)puVar5 + 6) = *(short *)((int)puVar5 + 6) - (ushort)DAT_803dc070,
       *(short *)((int)puVar5 + 6) < 1)) {
      *(undefined2 *)((int)puVar5 + 6) = 0;
      *(undefined *)(puVar5 + 3) = 0;
    }
    if (((*(char *)(puVar5 + 3) != '\0') && (*(short *)(puVar5 + 1) < 1)) &&
       (*(char *)((int)puVar5 + 0xd) != '\0')) {
      *(undefined *)((int)puVar5 + 0xd) = 0;
      FUN_8000bb38(param_1,0x80);
    }
    if (*(char *)(puVar5 + 3) != *(char *)((int)puVar5 + 0xe)) {
      if (*(char *)(puVar5 + 3) == '\0') {
        FUN_8000b7dc(param_1,0x7f);
        (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((*puVar5 != 0xffffffff) && (uVar3 = FUN_80020078(*puVar5), uVar3 != 0)) {
          FUN_800201ac(*puVar5,0);
        }
        if ((DAT_803de850 == '\x01') && (*(char *)((int)puVar5 + 0xf) == '\0')) {
          DAT_803de850 = '\0';
        }
        if ((DAT_803de850 == '\x02') && (*(char *)((int)puVar5 + 0xf) == '\x01')) {
          DAT_803de850 = '\0';
        }
        if (((DAT_803de850 == '\x03') && (*(char *)((int)puVar5 + 0xf) == '\x02')) &&
           (uVar3 = FUN_80020078(0x474), uVar3 == 0)) {
          FUN_800201ac(0x472,0);
          DAT_803de850 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80013ee8(0x69);
        local_40 = (uint)*(byte *)((int)puVar5 + 0xf) * 2;
        local_44 = local_40 + 0x19d;
        local_40 = local_40 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack_38,0x10004,0xffffffff,&local_48);
        FUN_80013e4c((undefined *)piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 200);
        if ((*puVar5 != 0xffffffff) && (uVar3 = FUN_80020078(*puVar5), uVar3 == 0)) {
          FUN_800201ac(*puVar5,1);
        }
        if (((DAT_803de850 == '\0') && (*(char *)((int)puVar5 + 0xf) == '\0')) &&
           (uVar3 = FUN_80020078(*puVar5), uVar3 != 0)) {
          DAT_803de850 = '\x01';
        }
        if (((DAT_803de850 == '\x01') && (*(char *)((int)puVar5 + 0xf) == '\x01')) &&
           (uVar3 = FUN_80020078(*puVar5), uVar3 != 0)) {
          DAT_803de850 = '\x02';
        }
        if (((DAT_803de850 == '\x02') && (*(char *)((int)puVar5 + 0xf) == '\x02')) &&
           (uVar3 = FUN_80020078(*puVar5), uVar3 != 0)) {
          FUN_800201ac(0x472,1);
          DAT_803de850 = '\x03';
        }
        *(undefined *)((int)puVar5 + 0xd) = 1;
        *(undefined2 *)(puVar5 + 1) = 1;
      }
    }
  }
  return;
}

