// Function: FUN_801a5e10
// Entry: 801a5e10
// Size: 1044 bytes

/* WARNING: Removing unreachable block (ram,0x801a6204) */
/* WARNING: Removing unreachable block (ram,0x801a5e20) */

void FUN_801a5e10(void)

{
  ushort uVar1;
  ushort *puVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  uint *puVar7;
  double dVar8;
  double dVar9;
  double in_f31;
  double in_ps31_1;
  int local_68;
  float afStack_64 [3];
  float local_58;
  float local_54;
  undefined4 local_50;
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar2 = (ushort *)FUN_80286838();
  local_58 = DAT_802c2a78;
  local_54 = DAT_802c2a7c;
  local_50 = DAT_802c2a80;
  puVar7 = *(uint **)(puVar2 + 0x5c);
  iVar6 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002bac4();
  uVar4 = FUN_80020078(0xab9);
  if ((uVar4 == 0) &&
     (dVar8 = (double)FUN_80021754((float *)(puVar2 + 0xc),(float *)(iVar3 + 0x18)),
     dVar8 < (double)FLOAT_803e50dc)) {
    if (puVar7[2] != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,puVar2,0xffffffff);
    }
    FUN_800201ac(0xab9,1);
  }
  if (puVar7[2] == 0) {
    uVar4 = FUN_80020078((int)*(short *)(iVar6 + 0x1e));
    if (uVar4 == 0) {
      uVar4 = FUN_80020078((int)*(short *)(iVar6 + 0x20));
      puVar7[2] = uVar4;
      if (puVar7[2] != 0) {
        local_48 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar6 + 0x19) ^ 0x80000000);
        *(float *)(puVar2 + 4) =
             *(float *)(*(int *)(puVar2 + 0x28) + 4) * (float)(local_48 - DOUBLE_803e50d0) *
             FLOAT_803e50e0;
        if (*puVar7 == 0) {
          uVar4 = FUN_8001cd60(puVar2,0xff,0,0x4d,0);
          *puVar7 = uVar4;
        }
      }
    }
    else {
      if (*(char *)(puVar2 + 0x1b) == -1) {
        FUN_8000bb38(0,0x109);
      }
      if (*(char *)(puVar2 + 0x1b) == '\0') {
        if (*puVar7 != 0) {
          FUN_8001cc00(puVar7);
        }
      }
      else {
        *(char *)(puVar2 + 0x1b) = *(char *)(puVar2 + 0x1b) + -1;
        if (*puVar7 != 0) {
          local_48 = (double)CONCAT44(0x43300000,*(byte *)(puVar2 + 0x1b) >> 2 ^ 0x80000000);
          uStack_3c = (*(byte *)(puVar2 + 0x1b) >> 2) + 10 ^ 0x80000000;
          local_40 = 0x43300000;
          FUN_8001dcfc((double)(float)(local_48 - DOUBLE_803e50d0),
                       (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e50d0),
                       *puVar7);
        }
        *(float *)(puVar2 + 4) = *(float *)(puVar2 + 4) * FLOAT_803e50e4;
        uStack_3c = (int)(short)puVar2[2] ^ 0x80000000;
        local_40 = 0x43300000;
        iVar3 = (int)-(FLOAT_803e50e8 * FLOAT_803dc074 -
                      (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e50d0));
        local_48 = (double)(longlong)iVar3;
        puVar2[2] = (ushort)iVar3;
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar3 != 0x51) {
      FUN_8000da78((uint)puVar2,0x423);
    }
    piVar5 = FUN_80037048(0x4e,&local_68);
    uVar4 = puVar7[3];
    uVar1 = (ushort)puVar7[1];
    local_54 = FLOAT_803e50ec;
    dVar8 = (double)FLOAT_803e50f0;
    for (iVar3 = 0; iVar3 < local_68; iVar3 = iVar3 + 1) {
      dVar9 = (double)FUN_800217c8((float *)(puVar2 + 0xc),(float *)(*piVar5 + 0x18));
      if (dVar9 <= dVar8) {
        puVar2[2] = uVar1;
        FUN_8002b270(puVar2,&local_58,afStack_64);
        FUN_80247e94((float *)(puVar2 + 6),afStack_64,(float *)(*piVar5 + 0xc));
        *(ushort *)*piVar5 = *puVar2;
        *(ushort *)(*piVar5 + 4) = uVar1 + 0x8000;
        *(undefined4 *)(*piVar5 + 8) = *(undefined4 *)(puVar2 + 4);
        uVar1 = uVar1 + (short)(0x10000 / (int)uVar4);
      }
      piVar5 = piVar5 + 1;
    }
    puVar7[1] = puVar7[1] + (int)DAT_803dcb38;
    puVar2[2] = 0;
    if (local_68 == 0) {
      puVar7[2] = 0;
      FUN_800201ac((int)*(short *)(iVar6 + 0x1e),1);
      FUN_80035ff8((int)puVar2);
    }
    iVar3 = FUN_800395a4((int)puVar2,0);
    if (iVar3 != 0) {
      *(ushort *)(iVar3 + 10) = *(short *)(iVar3 + 10) + (short)DAT_803dcb3c * (ushort)DAT_803dc070;
      *(ushort *)(iVar3 + 8) = *(short *)(iVar3 + 8) + (short)DAT_803dcb3c * (ushort)DAT_803dc070;
      if (DAT_803dcb40 << 8 < (int)*(short *)(iVar3 + 10)) {
        *(short *)(iVar3 + 10) = *(short *)(iVar3 + 10) - (short)(DAT_803dcb40 << 8);
      }
      if (DAT_803dcb40 << 8 < (int)*(short *)(iVar3 + 8)) {
        *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) - (short)(DAT_803dcb40 << 8);
      }
    }
    if (*(char *)(puVar2 + 0x1b) != -1) {
      *(char *)(puVar2 + 0x1b) = *(char *)(puVar2 + 0x1b) + '\x01';
    }
  }
  FUN_80286884();
  return;
}

