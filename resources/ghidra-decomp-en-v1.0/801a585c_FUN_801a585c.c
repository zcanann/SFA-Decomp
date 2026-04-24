// Function: FUN_801a585c
// Entry: 801a585c
// Size: 1044 bytes

/* WARNING: Removing unreachable block (ram,0x801a5c50) */

void FUN_801a585c(void)

{
  short sVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int *piVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f31;
  int local_68;
  undefined auStack100 [12];
  undefined4 local_58;
  float local_54;
  undefined4 local_50;
  double local_48;
  undefined4 local_40;
  uint uStack60;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  puVar2 = (undefined2 *)FUN_802860d4();
  local_58 = DAT_802c22f8;
  local_54 = DAT_802c22fc;
  local_50 = DAT_802c2300;
  piVar7 = *(int **)(puVar2 + 0x5c);
  iVar6 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002b9ec();
  iVar4 = FUN_8001ffb4(0xab9);
  if ((iVar4 == 0) &&
     (dVar9 = (double)FUN_80021690(puVar2 + 0xc,iVar3 + 0x18), dVar9 < (double)FLOAT_803e4444)) {
    if (piVar7[2] != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,puVar2,0xffffffff);
    }
    FUN_800200e8(0xab9,1);
  }
  if (piVar7[2] == 0) {
    iVar3 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x1e));
    if (iVar3 == 0) {
      iVar3 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x20));
      piVar7[2] = iVar3;
      if (piVar7[2] != 0) {
        local_48 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar6 + 0x19) ^ 0x80000000);
        *(float *)(puVar2 + 4) =
             *(float *)(*(int *)(puVar2 + 0x28) + 4) * (float)(local_48 - DOUBLE_803e4438) *
             FLOAT_803e4448;
        if (*piVar7 == 0) {
          iVar3 = FUN_8001cc9c(puVar2,0xff,0,0x4d,0);
          *piVar7 = iVar3;
        }
      }
    }
    else {
      if (*(char *)(puVar2 + 0x1b) == -1) {
        FUN_8000bb18(0,0x109);
      }
      if (*(char *)(puVar2 + 0x1b) == '\0') {
        if (*piVar7 != 0) {
          FUN_8001cb3c(piVar7);
        }
      }
      else {
        *(char *)(puVar2 + 0x1b) = *(char *)(puVar2 + 0x1b) + -1;
        if (*piVar7 != 0) {
          local_48 = (double)CONCAT44(0x43300000,*(byte *)(puVar2 + 0x1b) >> 2 ^ 0x80000000);
          uStack60 = (*(byte *)(puVar2 + 0x1b) >> 2) + 10 ^ 0x80000000;
          local_40 = 0x43300000;
          FUN_8001dc38((double)(float)(local_48 - DOUBLE_803e4438),
                       (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4438));
        }
        *(float *)(puVar2 + 4) = *(float *)(puVar2 + 4) * FLOAT_803e444c;
        uStack60 = (int)(short)puVar2[2] ^ 0x80000000;
        local_40 = 0x43300000;
        iVar3 = (int)-(FLOAT_803e4450 * FLOAT_803db414 -
                      (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4438));
        local_48 = (double)(longlong)iVar3;
        puVar2[2] = (short)iVar3;
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dca50 + 0x10))();
    if (iVar3 != 0x51) {
      FUN_8000da58(puVar2,0x423);
    }
    piVar5 = (int *)FUN_80036f50(0x4e,&local_68);
    iVar3 = piVar7[3];
    sVar1 = (short)piVar7[1];
    local_54 = FLOAT_803e4454;
    dVar9 = (double)FLOAT_803e4458;
    for (iVar4 = 0; iVar4 < local_68; iVar4 = iVar4 + 1) {
      dVar10 = (double)FUN_80021704(puVar2 + 0xc,*piVar5 + 0x18);
      if (dVar10 <= dVar9) {
        puVar2[2] = sVar1;
        FUN_8002b198(puVar2,&local_58,auStack100);
        FUN_80247730(puVar2 + 6,auStack100,*piVar5 + 0xc);
        *(undefined2 *)*piVar5 = *puVar2;
        *(short *)(*piVar5 + 4) = sVar1 + -0x8000;
        *(undefined4 *)(*piVar5 + 8) = *(undefined4 *)(puVar2 + 4);
        sVar1 = sVar1 + (short)(0x10000 / iVar3);
      }
      piVar5 = piVar5 + 1;
    }
    piVar7[1] = piVar7[1] + (int)DAT_803dbed0;
    puVar2[2] = 0;
    if (local_68 == 0) {
      piVar7[2] = 0;
      FUN_800200e8((int)*(short *)(iVar6 + 0x1e),1);
      FUN_80035f00(puVar2);
    }
    iVar3 = FUN_800394ac(puVar2,0,0);
    if (iVar3 != 0) {
      *(ushort *)(iVar3 + 10) = *(short *)(iVar3 + 10) + (short)DAT_803dbed4 * (ushort)DAT_803db410;
      *(ushort *)(iVar3 + 8) = *(short *)(iVar3 + 8) + (short)DAT_803dbed4 * (ushort)DAT_803db410;
      if (DAT_803dbed8 << 8 < (int)*(short *)(iVar3 + 10)) {
        *(short *)(iVar3 + 10) = *(short *)(iVar3 + 10) - (short)(DAT_803dbed8 << 8);
      }
      if (DAT_803dbed8 << 8 < (int)*(short *)(iVar3 + 8)) {
        *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) - (short)(DAT_803dbed8 << 8);
      }
    }
    if (*(char *)(puVar2 + 0x1b) != -1) {
      *(char *)(puVar2 + 0x1b) = *(char *)(puVar2 + 0x1b) + '\x01';
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286120();
  return;
}

