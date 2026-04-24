// Function: FUN_801126e0
// Entry: 801126e0
// Size: 840 bytes

void FUN_801126e0(void)

{
  float fVar1;
  ushort uVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  int in_r7;
  int in_r8;
  undefined2 in_r9;
  int in_r10;
  int iVar9;
  undefined8 uVar10;
  float local_48;
  undefined4 local_44;
  float local_40;
  undefined4 local_3c;
  int local_38;
  undefined local_34 [3];
  undefined uStack49;
  undefined4 local_30;
  uint uStack44;
  
  uVar10 = FUN_802860cc();
  iVar5 = (int)((ulonglong)uVar10 >> 0x20);
  iVar8 = (int)uVar10;
  iVar9 = *(int *)(iVar5 + 0xb8);
  uVar6 = FUN_8002b9ec();
  fVar3 = FLOAT_803e1c2c;
  if (FLOAT_803e1c2c < *(float *)(iVar9 + 1000)) {
    *(float *)(iVar9 + 1000) = FLOAT_803db414 * *(float *)(iVar9 + 0x3ec) + *(float *)(iVar9 + 1000)
    ;
    uVar2 = *(ushort *)(iVar9 + 0x400);
    if ((uVar2 & 0x20) == 0) {
      if ((uVar2 & 0x40) == 0) {
        fVar1 = *(float *)(iVar9 + 1000);
        if (fVar3 <= fVar1) {
          if (FLOAT_803e1c44 < fVar1) {
            *(float *)(iVar9 + 1000) = FLOAT_803e1c44 - (fVar1 - FLOAT_803e1c44);
            *(float *)(iVar9 + 0x3ec) = -*(float *)(iVar9 + 0x3ec);
          }
        }
        else {
          *(float *)(iVar9 + 1000) = fVar3;
        }
      }
      else if (FLOAT_803e1c40 < *(float *)(iVar9 + 1000)) {
        iVar7 = *(int *)(iVar5 + 0x4c);
        *(float *)(iVar9 + 1000) = fVar3;
        *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) & 0xffbf;
        *(undefined *)(iVar8 + 0x354) = 0;
        *(undefined *)(iVar5 + 0x36) = 0;
        *(undefined4 *)(iVar5 + 0xf4) = 1;
        *(ushort *)(iVar5 + 6) = *(ushort *)(iVar5 + 6) | 0x4000;
        uStack44 = *(short *)(iVar7 + 0x2c) * 0x3c ^ 0x80000000;
        local_30 = 0x43300000;
        (**(code **)(*DAT_803dcaac + 100))
                  ((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1c30),
                   *(undefined4 *)(iVar7 + 0x14));
      }
    }
    else {
      *(ushort *)(iVar9 + 0x400) = uVar2 & 0xffdf;
      *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) | 0x40;
      if (FLOAT_803e1c40 < *(float *)(iVar9 + 1000)) {
        *(float *)(iVar9 + 1000) = fVar3;
        *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) & 0xffbf;
      }
    }
  }
  if (*(char *)(iVar8 + 0x354) == '\0') {
    iVar7 = 0;
  }
  else {
    iVar7 = FUN_80036770(iVar5,&local_3c,local_34,&local_38,&local_40,&local_44,&local_48);
    *(undefined *)(iVar9 + 0x40a) = uStack49;
    if (iVar7 != 0) {
      if (in_r10 != 0) {
        *(float *)(in_r10 + 0xc) = local_40 + FLOAT_803dcdd8;
        *(undefined4 *)(in_r10 + 0x10) = local_44;
        *(float *)(in_r10 + 0x14) = local_48 + FLOAT_803dcddc;
      }
      if (in_r8 == 0) {
        local_38 = 0;
      }
      else {
        iVar4 = (int)*(char *)(in_r8 + iVar7 + -2);
        if (iVar4 != -1) {
          local_38 = iVar4;
        }
      }
      *(char *)(iVar8 + 0x354) = *(char *)(iVar8 + 0x354) - (char)local_38;
      if (*(char *)(iVar8 + 0x354) < '\x01') {
        *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) | 0x20;
        *(float *)(iVar9 + 1000) = FLOAT_803e1c48;
        *(float *)(iVar9 + 0x3ec) = FLOAT_803e1c4c;
        *(undefined2 *)(iVar8 + 0x270) = in_r9;
        *(undefined *)(iVar8 + 0x354) = 0;
      }
      else if (local_38 != 0) {
        if ((*(int *)(iVar8 + 0x2d0) == 0) && (iVar4 = FUN_80295a04(uVar6,1), iVar4 != 0)) {
          *(undefined4 *)(iVar8 + 0x2d0) = uVar6;
          *(undefined *)(iVar8 + 0x349) = 0;
        }
        *(float *)(iVar9 + 1000) = FLOAT_803e1c48;
        *(float *)(iVar9 + 0x3ec) = FLOAT_803e1c50;
        if ((in_r7 != 0) && (*(int *)(in_r7 + iVar7 * 4 + -8) != -1)) {
          (**(code **)(*DAT_803dca8c + 0x14))(iVar5,iVar8);
          *(undefined2 *)(iVar8 + 0x270) = in_r9;
        }
        *(char *)(iVar8 + 0x34f) = (char)iVar7;
      }
      FUN_8000b7bc(iVar5,0x10);
      FUN_800378c4(local_3c,0xe0001,iVar5,0);
    }
  }
  FUN_80286118(iVar7);
  return;
}

